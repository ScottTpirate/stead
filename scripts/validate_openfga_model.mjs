#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const testsPath = path.join(root, "policies/openfga/model-tests.yaml");
const testDocument = YAML.parse(fs.readFileSync(testsPath, "utf8"));
const modelPath = path.resolve(path.dirname(testsPath), testDocument.model_file);
const modelSource = fs.readFileSync(modelPath, "utf8");

function splitExpression(source, operator) {
  return source.split(` ${operator} `).map((part) => part.trim());
}

function parseExpression(source) {
  const alternatives = splitExpression(source, "or");
  if (alternatives.length > 1) return {kind: "or", children: alternatives.map(parseExpression)};

  const intersections = splitExpression(source, "and");
  if (intersections.length > 1) return {kind: "and", children: intersections.map(parseExpression)};

  const direct = source.match(/^\[([^\]]+)\]$/);
  if (direct) {
    return {kind: "direct", allowed: direct[1].split(",").map((value) => value.trim())};
  }

  const from = source.match(/^([a-z][a-z0-9_]*) from ([a-z][a-z0-9_]*)$/);
  if (from) return {kind: "from", relation: from[1], tupleset: from[2]};

  if (/^[a-z][a-z0-9_]*$/.test(source)) return {kind: "computed", relation: source};
  throw new Error(`unsupported OpenFGA relation expression: ${source}`);
}

function parseModel(source) {
  const model = new Map();
  let currentType = null;
  let sawSchema = false;

  for (const rawLine of source.split(/\r?\n/)) {
    const line = rawLine.replace(/\s+#.*$/, "").trim();
    if (!line || line === "model" || line === "relations") continue;
    if (line === "schema 1.1") {
      sawSchema = true;
      continue;
    }

    const typeMatch = line.match(/^type ([a-z][a-z0-9_]*)$/);
    if (typeMatch) {
      currentType = typeMatch[1];
      if (model.has(currentType)) throw new Error(`duplicate type ${currentType}`);
      model.set(currentType, new Map());
      continue;
    }

    const relationMatch = line.match(/^define ([a-z][a-z0-9_]*): (.+)$/);
    if (relationMatch && currentType) {
      const relations = model.get(currentType);
      if (relations.has(relationMatch[1])) {
        throw new Error(`duplicate relation ${currentType}#${relationMatch[1]}`);
      }
      relations.set(relationMatch[1], parseExpression(relationMatch[2]));
      continue;
    }

    throw new Error(`unsupported OpenFGA model syntax: ${line}`);
  }

  if (!sawSchema) throw new Error("OpenFGA model must declare schema 1.1");
  return model;
}

function objectType(object) {
  const separator = object.indexOf(":");
  if (separator <= 0 || separator === object.length - 1) {
    throw new Error(`invalid object or subject ${object}`);
  }
  return object.slice(0, separator);
}

function directNodes(expression) {
  if (expression.kind === "direct") return [expression];
  if (expression.kind === "or" || expression.kind === "and") {
    return expression.children.flatMap(directNodes);
  }
  return [];
}

function subjectRestriction(subject) {
  const [object, relation] = subject.split("#", 2);
  return `${objectType(object)}${relation ? `#${relation}` : ""}`;
}

function evaluateSuite(model, suite) {
  const tuples = suite.tuples || [];

  for (const tuple of tuples) {
    const relations = model.get(objectType(tuple.object));
    if (!relations?.has(tuple.relation)) {
      throw new Error(`${suite.name}: tuple targets unknown relation ${tuple.object}#${tuple.relation}`);
    }
    const assignable = directNodes(relations.get(tuple.relation));
    if (assignable.length === 0) {
      throw new Error(`${suite.name}: tuple writes computed-only relation ${tuple.object}#${tuple.relation}`);
    }
    const restriction = subjectRestriction(tuple.user);
    if (!assignable.some((node) => node.allowed.includes(restriction))) {
      throw new Error(`${suite.name}: ${restriction} is not assignable to ${tuple.object}#${tuple.relation}`);
    }
  }

  const memo = new Map();
  const evaluating = new Set();

  function check(user, relation, object) {
    const key = `${user}|${relation}|${object}`;
    if (memo.has(key)) return memo.get(key);
    if (evaluating.has(key)) return false;
    evaluating.add(key);

    const relations = model.get(objectType(object));
    const expression = relations?.get(relation);
    if (!expression) throw new Error(`${suite.name}: assertion targets unknown relation ${object}#${relation}`);

    const directMatch = () => tuples.some((tuple) => {
      if (tuple.object !== object || tuple.relation !== relation) return false;
      if (tuple.user === user) return true;
      const userset = tuple.user.match(/^([^#]+)#([a-z][a-z0-9_]*)$/);
      return userset ? check(user, userset[2], userset[1]) : false;
    });

    const evaluate = (node) => {
      switch (node.kind) {
        case "direct":
          return directMatch();
        case "computed":
          return check(user, node.relation, object);
        case "or":
          return node.children.some(evaluate);
        case "and":
          return node.children.every(evaluate);
        case "from":
          return tuples.some((tuple) =>
            tuple.object === object &&
            tuple.relation === node.tupleset &&
            !tuple.user.includes("#") &&
            check(user, node.relation, tuple.user));
        default:
          throw new Error(`${suite.name}: unknown evaluator node ${node.kind}`);
      }
    };

    const result = evaluate(expression);
    evaluating.delete(key);
    memo.set(key, result);
    return result;
  }

  let assertions = 0;
  for (const request of suite.check || []) {
    for (const [relation, expected] of Object.entries(request.assertions || {})) {
      assertions += 1;
      const actual = check(request.user, relation, request.object);
      if (actual !== expected) {
        throw new Error(
          `${suite.name}: ${request.user} ${relation} ${request.object} expected ${expected}, got ${actual}`,
        );
      }
    }
  }
  return assertions;
}

try {
  const model = parseModel(modelSource);
  const suites = testDocument.tests || [];
  let assertions = 0;
  for (const suite of suites) assertions += evaluateSuite(model, suite);
  if (suites.length < 16 || assertions < 80) {
    throw new Error(`coverage floor failed: ${suites.length} suites and ${assertions} assertions`);
  }

  const mutations = [
    modelSource.replaceAll(", directory_group#member", ""),
    modelSource.replace(
      "define agent_executor: agent_authority and delegated_executor_agent",
      "define agent_executor: agent_authority or delegated_executor_agent",
    ),
  ];
  for (const mutation of mutations) {
    let rejected = false;
    try {
      const mutatedModel = parseModel(mutation);
      for (const suite of suites) evaluateSuite(mutatedModel, suite);
    } catch {
      rejected = true;
    }
    if (!rejected) throw new Error("critical OpenFGA model mutation unexpectedly passed");
  }

  console.log(
    `OpenFGA contract model tests passed: ${suites.length}/${suites.length} suites, ${assertions}/${assertions} assertions, ${mutations.length} critical mutation guards`,
  );
} catch (error) {
  console.error(`OpenFGA contract model validation failed: ${error.message}`);
  process.exit(1);
}
