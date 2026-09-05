// SPDX-License-Identifier: Apache-2.0
// Generated configuration is private dev state, never product policy or fixtures.
export const servicePorts = Object.freeze({ postgres: 15432, gitea: 13000, openfga: 18080, openfgaGrpc: 18081, nats: 14222, natsMonitor: 18222, api: 18000, worker: 18001, web: 18443 });
export const serviceNames = Object.freeze(['postgres', 'gitea', 'openfga', 'nats', 'stead-api', 'stead-worker', 'stead-web']);

export function postgresURL(user, password, database, host = '127.0.0.1', port = servicePorts.postgres) {
  return `postgresql://${encodeURIComponent(user)}:${encodeURIComponent(password)}@${host}:${port}/${database}?sslmode=disable&connect_timeout=5`;
}

export function giteaConfig(secret, ports = servicePorts, host = '127.0.0.1') {
  return `APP_NAME = Stead local provider (not a product interface)
RUN_USER = git
RUN_MODE = prod
[server]
PROTOCOL = http
HTTP_ADDR = ${host}
HTTP_PORT = ${ports.gitea}
DOMAIN = localhost
ROOT_URL = http://localhost:${ports.gitea}/
DISABLE_SSH = true
START_SSH_SERVER = false
OFFLINE_MODE = true
LFS_START_SERVER = false
[database]
DB_TYPE = postgres
HOST = ${host}:${ports.postgres}
NAME = gitea
USER = gitea
PASSWD = ${secret.giteaPassword}
SSL_MODE = disable
[security]
INSTALL_LOCK = true
SECRET_KEY = ${secret.giteaSecret}
INTERNAL_TOKEN = ${secret.giteaInternalToken}
[service]
DISABLE_REGISTRATION = true
REQUIRE_SIGNIN_VIEW = true
ENABLE_NOTIFY_MAIL = false
ENABLE_BASIC_AUTHENTICATION = false
[mailer]
ENABLED = false
[oauth2]
ENABLED = false
[openid]
ENABLE_OPENID_SIGNIN = false
ENABLE_OPENID_SIGNUP = false
[repository]
DISABLE_MIGRATIONS = true
DISABLED_REPO_UNITS = repo.actions,repo.packages
[repository.upload]
ENABLED = false
[mirror]
ENABLED = false
[actions]
ENABLED = false
[packages]
ENABLED = false
[attachment]
ENABLED = false
[picture]
DISABLE_GRAVATAR = true
ENABLE_FEDERATED_AVATAR = false
[avatar]
MAX_WIDTH = 1
MAX_HEIGHT = 1
MAX_FILE_SIZE = 1
[log]
MODE = console
LEVEL = Warn
ENABLE_ACCESS_LOG = false
`;
}

export function natsConfig(secret, ports = servicePorts, host = '127.0.0.1') {
  // No users/Organization resources or consumer semantics are invented here.
  // WS-07 bootstrap owns the two fixed streams and its reviewed registry.
  return `server_name: stead-local
listen: ${host}:${ports.nats}
http: ${host}:${ports.natsMonitor}
max_payload: 1048576
max_connections: 32
write_deadline: "2s"
jetstream { store_dir: /data, max_memory_store: 67108864, max_file_store: 1073741824 }
accounts {
  STEAD {
    jetstream: enabled
    users: [
      { user: publisher, password: "${secret.natsPublisher}", permissions: { publish: ["stead.organization.changed.v1", "stead.project.changed.v1", "stead.identity.changed.v1", "stead.authorization.changed.v1", "stead.audit.changed.v1", "stead.dead_letter.recorded.v1", "$JS.API.STREAM.MSG.GET.STEAD_EVENTS_V1", "$JS.API.STREAM.INFO.STEAD_EVENTS_V1", "$JS.API.STREAM.MSG.GET.STEAD_DLQ_V1", "$JS.API.STREAM.INFO.STEAD_DLQ_V1"], subscribe: ["_INBOX.>"] } },
      { user: consumer, password: "${secret.natsConsumer}", permissions: { publish: ["$JS.API.CONSUMER.MSG.NEXT.STEAD_EVENTS_V1.*", "$JS.ACK.STEAD_EVENTS_V1.>"], subscribe: ["_INBOX.>"] } },
      { user: maintenance, password: "${secret.natsMaintenance}", permissions: { publish: ["$JS.API.STREAM.CREATE.STEAD_EVENTS_V1", "$JS.API.STREAM.CREATE.STEAD_DLQ_V1", "$JS.API.STREAM.INFO.STEAD_EVENTS_V1", "$JS.API.STREAM.INFO.STEAD_DLQ_V1", "$JS.API.CONSUMER.CREATE.STEAD_EVENTS_V1.>"], subscribe: ["_INBOX.>"] } }
    ]
  }
}
`;
}

export function openfgaEnvironment(secret, ports = servicePorts, host = '127.0.0.1') {
  return {
    OPENFGA_DATASTORE_ENGINE: 'postgres',
    OPENFGA_DATASTORE_URI: postgresURL('openfga', secret.openfgaPassword, 'openfga', host, ports.postgres),
    OPENFGA_AUTHN_METHOD: 'preshared',
    OPENFGA_AUTHN_PRESHARED_KEYS: secret.openfgaKey,
    OPENFGA_HTTP_ADDR: `${host}:${ports.openfga}`,
    OPENFGA_GRPC_ADDR: `${host}:${ports.openfgaGrpc}`,
    OPENFGA_HTTP_CORS_ALLOWED_ORIGINS: 'https://stead-internal.invalid',
    OPENFGA_PLAYGROUND_ENABLED: 'false',
    OPENFGA_METRICS_ENABLED: 'false',
    OPENFGA_TRACE_ENABLED: 'false',
    OPENFGA_CHECK_QUERY_CACHE_ENABLED: 'false',
    OPENFGA_CHECK_ITERATOR_CACHE_ENABLED: 'false',
    OPENFGA_LIST_OBJECTS_ITERATOR_CACHE_ENABLED: 'false',
    OPENFGA_DATASTORE_MAX_OPEN_CONNS: '8',
    OPENFGA_DATASTORE_MAX_IDLE_CONNS: '2',
    OPENFGA_LOG_LEVEL: 'warn',
    OPENFGA_LOG_FORMAT: 'json',
  };
}
