# frozen_string_literal: true

require "json"
require "pathname"
require "set"

module Stead
  module PerformanceStrictJSON
    MAX_JSON_BYTES = 128 * 1024 * 1024
    MAX_DEPTH = 32
    MAX_COLLECTION_ENTRIES = 100_000
    MAX_TOTAL_VALUES = 4_000_000
    MAX_STRING_BYTES = 65_536

    class Error < JSON::ParserError; end

    module_function

    def parse_file(path, max_bytes: MAX_JSON_BYTES)
      path = Pathname(path)
      size = path.size
      raise Error, "JSON input exceeds #{max_bytes} bytes" if size > max_bytes

      bytes = File.open(path, "rb") { |file| file.read(max_bytes + 1) }
      raise Error, "JSON input exceeds #{max_bytes} bytes" if bytes.bytesize > max_bytes

      parse(bytes)
    end

    def parse(source, max_bytes: MAX_JSON_BYTES)
      raise Error, "JSON input must be a string" unless source.is_a?(String)
      raise Error, "JSON input exceeds #{max_bytes} bytes" if source.bytesize > max_bytes

      source = source.dup.force_encoding(Encoding::UTF_8)
      raise Error, "JSON input is not valid UTF-8" unless source.valid_encoding?

      Scanner.new(source).validate!
      JSON.parse(source, max_nesting: MAX_DEPTH)
    rescue JSON::NestingError => error
      raise Error, error.message
    end

    class Scanner
      SIMPLE_ESCAPES = {
        0x22 => '"', 0x5c => "\\", 0x2f => "/", 0x62 => "\b",
        0x66 => "\f", 0x6e => "\n", 0x72 => "\r", 0x74 => "\t"
      }.freeze

      def initialize(source)
        @source = source
        @index = 0
        @values = 0
      end

      def validate!
        whitespace
        value(0)
        whitespace
        fail_at("trailing content") unless eof?
        true
      end

      private

      def value(depth)
        @values += 1
        fail_at("JSON value cardinality exceeds #{MAX_TOTAL_VALUES}") if @values > MAX_TOTAL_VALUES
        fail_at("JSON nesting exceeds #{MAX_DEPTH}") if depth > MAX_DEPTH

        case byte
        when 0x7b then object(depth + 1)
        when 0x5b then array(depth + 1)
        when 0x22 then string(capture: false)
        when 0x74 then literal("true")
        when 0x66 then literal("false")
        when 0x6e then literal("null")
        when 0x2d, 0x30..0x39 then number
        else fail_at("expected JSON value")
        end
      end

      def object(depth)
        consume(0x7b)
        whitespace
        return consume(0x7d) if byte == 0x7d

        keys = Set.new
        entries = 0
        loop do
          fail_at("object key must be a string") unless byte == 0x22
          key = string(capture: true)
          fail_at("duplicate object key") unless keys.add?(key)
          entries += 1
          fail_at("object cardinality exceeds #{MAX_COLLECTION_ENTRIES}") if entries > MAX_COLLECTION_ENTRIES
          whitespace
          consume(0x3a)
          whitespace
          value(depth)
          whitespace
          break consume(0x7d) if byte == 0x7d

          consume(0x2c)
          whitespace
        end
      end

      def array(depth)
        consume(0x5b)
        whitespace
        return consume(0x5d) if byte == 0x5d

        entries = 0
        loop do
          entries += 1
          fail_at("array cardinality exceeds #{MAX_COLLECTION_ENTRIES}") if entries > MAX_COLLECTION_ENTRIES
          value(depth)
          whitespace
          break consume(0x5d) if byte == 0x5d

          consume(0x2c)
          whitespace
        end
      end

      def string(capture:)
        consume(0x22)
        decoded = +"" if capture
        decoded_bytes = 0
        loop do
          fail_at("unterminated string") if eof?
          current = byte
          if current == 0x22
            @index += 1
            return decoded
          end
          fail_at("unescaped control character") if current < 0x20

          if current == 0x5c
            @index += 1
            escaped = byte
            if SIMPLE_ESCAPES.key?(escaped)
              decoded << SIMPLE_ESCAPES.fetch(escaped) if capture
              decoded_bytes += 1
              @index += 1
            elsif escaped == 0x75
              character = unicode_escape
              decoded << character if capture
              decoded_bytes += character.bytesize
            else
              fail_at("invalid string escape")
            end
          elsif current < 0x80
            decoded << current if capture
            decoded_bytes += 1
            @index += 1
          else
            width = utf8_width(current)
            fail_at("invalid UTF-8 in string") if width.zero? || @index + width > @source.bytesize
            segment = @source.byteslice(@index, width)
            fail_at("invalid UTF-8 in string") unless segment.dup.force_encoding(Encoding::UTF_8).valid_encoding?
            decoded << segment if capture
            decoded_bytes += width
            @index += width
          end
          fail_at("decoded string exceeds #{MAX_STRING_BYTES} bytes") if decoded_bytes > MAX_STRING_BYTES
        end
      end

      def unicode_escape
        consume(0x75)
        first = hex_code_unit
        codepoint = if first.between?(0xd800, 0xdbff)
                      consume(0x5c)
                      consume(0x75)
                      second = hex_code_unit
                      fail_at("invalid Unicode surrogate pair") unless second.between?(0xdc00, 0xdfff)
                      0x10000 + ((first - 0xd800) << 10) + (second - 0xdc00)
                    else
                      fail_at("unpaired Unicode surrogate") if first.between?(0xdc00, 0xdfff)
                      first
                    end
        [codepoint].pack("U")
      end

      def hex_code_unit
        fail_at("truncated Unicode escape") if @index + 4 > @source.bytesize
        digits = @source.byteslice(@index, 4)
        fail_at("invalid Unicode escape") unless digits.match?(/\A[0-9A-Fa-f]{4}\z/)
        @index += 4
        digits.to_i(16)
      end

      def number
        @index += 1 if byte == 0x2d
        fail_at("invalid number") if eof?
        if byte == 0x30
          @index += 1
          fail_at("leading zero in number") if digit?(byte)
        else
          fail_at("invalid number") unless byte&.between?(0x31, 0x39)
          @index += 1 while digit?(byte)
        end
        if byte == 0x2e
          @index += 1
          fail_at("invalid fractional number") unless digit?(byte)
          @index += 1 while digit?(byte)
        end
        if byte == 0x65 || byte == 0x45
          @index += 1
          @index += 1 if byte == 0x2b || byte == 0x2d
          fail_at("invalid exponent") unless digit?(byte)
          @index += 1 while digit?(byte)
        end
      end

      def literal(expected)
        fail_at("invalid literal") unless @source.byteslice(@index, expected.bytesize) == expected
        @index += expected.bytesize
      end

      def whitespace
        @index += 1 while [0x20, 0x09, 0x0a, 0x0d].include?(byte)
      end

      def consume(expected)
        fail_at("expected #{expected.chr.inspect}") unless byte == expected
        @index += 1
        true
      end

      def digit?(value)
        value&.between?(0x30, 0x39)
      end

      def utf8_width(first)
        return 1 if first < 0x80
        return 2 if first.between?(0xc2, 0xdf)
        return 3 if first.between?(0xe0, 0xef)
        return 4 if first.between?(0xf0, 0xf4)

        0
      end

      def byte
        @source.getbyte(@index)
      end

      def eof?
        @index >= @source.bytesize
      end

      def fail_at(message)
        raise Error, "#{message} at byte #{@index}"
      end
    end
  end
end
