"""Risk classes: WHAT a change can break, read from the added and removed
lines themselves, not from the file name alone.

`sensitive_paths` says "this file is called auth.py". This module says
"this diff turns certificate checking off", "this workflow runs a fork's code
with the repository's secrets", "this lockfile changed and the manifest did
not", "this line talks to the review bot", "this character reorders the
code on screen". Deterministic regular expressions over a unified diff, no
model, no network. Every finding names the file, the line and the reason, so
a person can argue with it.

Classes (severity: critical 15, high 8, medium 4, low 1 points, a class
counts once at its highest severity, all classes together capped at 25):

  hidden_text         bidi / invisible / tag characters, mixed-script words
  prompt_injection    sentences addressed to an AI reviewer
  secret              keys, tokens, private keys, committed key files
  ci_workflow         CI configuration changed; pull_request_target,
                      script injection, unpinned actions, write-all
  dependency          manifests and lockfiles; lockfile without manifest;
                      non-registry sources
  install_script      code that runs at install time
  remote_script       curl | sh and friends
  unsafe_exec         eval, shell=True, pickle, innerHTML, ...
  weak_control        TLS verification off, csrf off, jwt "none", CORS *
  weak_crypto         md5/sha1/ecb/DES, Math.random for secrets
  permissions         chmod 777, privileged containers, "*" in IAM, 0.0.0.0/0
  destructive_migration  DROP / TRUNCATE / remove-column
  iac                 infrastructure files
  guard_removed       an auth/validation call that the diff takes out
  test_weakening      skipped tests, removed assertions, `|| true` in CI
  scan_limit          the scan could not search everything (a line padded
                      past 4,000 characters, a file past 100,000 added lines)

What it cannot see: anything that is not in the added or removed lines
(a one-line change that is dangerous only because of the code around it), and
code a regular expression cannot tell from prose. Comment-only lines are not
searched for code patterns, but they are for hidden text and injection.
"""

from __future__ import annotations

import dataclasses
import fnmatch
import math
import re

from . import hidden

SEVERITY_POINTS = {"critical": 15, "high": 8, "medium": 4, "low": 1}
SEVERITY_ORDER = ("critical", "high", "medium", "low")
MAX_POINTS = 25
#: findings kept per file and in all; the rest are counted, not listed
MAX_PER_FILE = 40
MAX_TOTAL = 400
#: lines of one file searched; a lockfile of 50,000 lines is searched for
#: sources, not line by line for everything
MAX_LINES_PER_FILE = 100000
#: added lines searched in one run; the rest of a very large pull request is
#: reported as `scan_limit`, so the scan stays near ten seconds.
MAX_LINES_TOTAL = 500000
MAX_LINE_CHARS = 4000
#: a longer line is searched in windows of MAX_LINE_CHARS that overlap by
#: WINDOW_OVERLAP (a pattern cut by a window edge is whole in the next), up
#: to MAX_WINDOWS_PER_LINE windows, and MAX_WINDOWS_PER_FILE in a file; what
#: is past that is reported as a `scan_limit` finding, never skipped quietly.
WINDOW_OVERLAP = 200
MAX_WINDOWS_PER_LINE = 64
MAX_WINDOWS_PER_FILE = 4000

CLASSES = ("hidden_text", "prompt_injection", "secret", "ci_workflow",
           "dependency", "install_script", "remote_script", "unsafe_exec",
           "weak_control", "weak_crypto", "permissions",
           "destructive_migration", "iac", "guard_removed", "test_weakening",
           "scan_limit")


@dataclasses.dataclass(frozen=True)
class Finding:
    cls: str
    severity: str
    file: str
    line: int          # 0: the file as a whole
    why: str

    def as_dict(self) -> dict:
        return dataclasses.asdict(self)


# --- file kinds ----------------------------------------------------------------

def _norm(path: str) -> str:
    return path.replace("\\", "/")


_WORKFLOW = re.compile(
    r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|Jenkinsfile[^/]*|"
    r"\.circleci/[^/]+|azure-pipelines\.ya?ml|bitbucket-pipelines\.ya?ml|"
    r"\.buildkite/[^/]+|\.drone\.ya?ml|cloudbuild\.ya?ml)$", re.I)
_GH_WORKFLOW = re.compile(r"(^|/)\.github/workflows/[^/]+\.ya?ml$", re.I)  # noqa: F841
_COMPOSITE_ACTION = re.compile(r"(^|/)action\.ya?ml$", re.I)
_LOCKFILE = re.compile(
    r"(^|/)(package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.ya?ml|"
    r"bun\.lockb?|poetry\.lock|Pipfile\.lock|uv\.lock|pdm\.lock|Cargo\.lock|"
    r"go\.sum|Gemfile\.lock|composer\.lock|packages\.lock\.json|gradle\.lockfile|"
    r"Podfile\.lock|mix\.lock|pubspec\.lock|flake\.lock)$", re.I)
_MANIFEST = re.compile(
    r"(^|/)(package\.json|pyproject\.toml|Pipfile|setup\.py|setup\.cfg|"
    r"requirements[^/]*\.(txt|in)|constraints[^/]*\.txt|Cargo\.toml|go\.mod|"
    r"Gemfile|[^/]+\.gemspec|composer\.json|pom\.xml|build\.gradle(\.kts)?|"
    r"[^/]+\.csproj|Directory\.Packages\.props|mix\.exs|pubspec\.yaml|"
    r"Package\.swift|Podfile|environment\.ya?ml)$", re.I)
_MIGRATION = re.compile(
    r"(^|/)(migrations?|migrate|alembic/versions|db/migrate|flyway|liquibase)/|"
    r"\.sql$", re.I)
_IAC = re.compile(
    r"(\.tf$|\.tfvars$|\.bicep$|(^|/)Dockerfile[^/]*$|\.dockerfile$|"
    r"(^|/)docker-compose[^/]*\.ya?ml$|(^|/)compose\.ya?ml$|"
    r"(^|/)(k8s|kubernetes|manifests?|helm|charts?|ansible|terraform|pulumi|"
    r"cloudformation|infra|infrastructure|deploy)/[^\n]*\.(ya?ml|json|tpl)$|"
    r"(^|/)(serverless|template|samconfig)\.(ya?ml|toml)$|"
    r"(^|/)Chart\.ya?ml$|(^|/)Vagrantfile$|(^|/)nginx[^/]*\.conf$)", re.I)
_SECRET_FILE = re.compile(
    r"(^|/)(\.env(\.[\w.-]+)?|id_(rsa|dsa|ecdsa|ed25519)|[^/]+\.(pem|p12|pfx|jks|keystore)|"
    r"credentials(\.json)?|service[-_]account[^/]*\.json|\.netrc|\.pgpass|"
    r"\.htpasswd|secrets?\.(ya?ml|json|toml))$", re.I)
_SECRET_FILE_OK = re.compile(
    r"\.(example|sample|template|dist|tpl|defaults?)$|(^|/)\.env\.(example|sample|template|dist)$",
    re.I)
_TEST = re.compile(
    r"(^|/)(tests?|__tests__|spec|specs|testing|e2e|cypress)/|"
    r"(^|/)(test_[^/]*|conftest\.py|[^/]*_test\.[^/]+|[^/]*\.(test|spec)\.[^/]+|"
    r"[^/]*(Test|Tests)\.(java|kt|cs)|[^/]*_spec\.rb)$")
_DOC = re.compile(r"\.(md|markdown|rst|txt|adoc)$|(^|/)(docs?|documentation)/", re.I)
_CODE = re.compile(
    r"\.(py|js|jsx|ts|tsx|mjs|cjs|rb|php|java|kt|scala|go|rs|c|cc|cpp|h|hpp|cs|"
    r"swift|sh|bash|zsh|ksh|fish|ps1|psm1|pl|pm|lua|groovy|gradle|vue|svelte|"
    r"pyw|phtml|php\d|inc|ex|exs|erl|dart|bat|cmd|mk|jl|r)$|"
    # extensionless scripts and build files: a payload goes where nobody looks
    r"(^|/)(Makefile|GNUmakefile|Rakefile|Fastfile|Podfile|Brewfile|Procfile|"
    r"Justfile|Taskfile)$|(^|/)(bin|sbin|scripts?|libexec|hooks)/[^/.]+$", re.I)


# --- line rules ----------------------------------------------------------------

_COMMENT_START = re.compile(r"^\s*(#|//|\*|/\*|--\s|;|<!--|\"\"\"|''')")


def _rx(pattern: str, flags: int = 0) -> "re.Pattern[str]":
    return re.compile(pattern, flags)


class _Quick:
    """A cheap test in front of a group of rules: does the line contain any
    of these substrings at all? Plain `in` tests on the lower-cased line are
    many times faster than running every rule's regular expression on every
    line, and the ordinary line contains none. The substrings must cover
    every rule of the group (the benchmark would show a rule gone silent)."""

    def __init__(self, keys, raw: bool = False):
        keys = list(keys if raw else [k.lower() for k in keys])
        self.rx = re.compile("|".join(re.escape(k) for k in keys))
        self.raw = raw

    def __call__(self, text: str, low: str) -> bool:
        return self.rx.search(text if self.raw else low) is not None


#: (class, severity, why, regex)
_CODE_RULES = [
    ("unsafe_exec", "high", "eval of a string", _rx(r"(?<![\w.])eval\s*\(")),
    ("unsafe_exec", "high", "exec of a string", _rx(r"(?<![\w.])exec\s*\(\s*[^)\s]")),
    ("unsafe_exec", "high", "new Function from a string", _rx(r"\bnew\s+Function\s*\(")),
    ("unsafe_exec", "high", "shell command from a string",
     _rx(r"\bos\.(system|popen)\s*\(|\bshell_exec\s*\(|\bpassthru\s*\(|"
         r"\bRuntime\.getRuntime\(\)\.exec\(|\bexec\.Command\(\s*\"(sh|bash|cmd)\"")),
    ("unsafe_exec", "high", "SQL built from a string",
     _rx(r"\b(execute|executemany|raw|query|prepare)\s*\(\s*(?:f[\"'][^\"']*\b(select|insert|update|delete)\b[^\"']*\{|"
         r"[^)]{0,200}?\b(select|insert|update|delete)\b[^)]{0,200}?"
         r"(?:[\"'`]\s*\+\s*[\w(]|\$\{|\.format\(|[\"']\s*%\s*[\w(]))", re.I)),
    ("unsafe_exec", "high", "shell command from a string",
     _rx(r"(?<![\w.>:$])(system|passthru|popen|proc_open)\s*\(\s*\$\w|"
         r"__import__\s*\([^)]*\)\s*\.\s*(system|popen)\b|"
         r"\bgetattr\s*\(\s*os\s*,\s*[\"'](system|popen)[\"']")),
    ("unsafe_exec", "high", "subprocess with shell=True",
     _rx(r"\bsubprocess\.\w+\([^)]*shell\s*=\s*True|\bshell\s*=\s*True\b")),
    ("unsafe_exec", "high", "child_process exec of a string",
     _rx(r"\bchild_process\b.*\bexec(Sync)?\s*\(|(?<![\w.])exec(Sync)?\s*\(\s*[`\"'][^`\"']*(\$\{|\"\s*\+|'\s*\+)")),
    ("unsafe_exec", "high", "unpickling / unsafe deserialisation",
     _rx(r"\bpickle\.loads?\(|\bcPickle\.loads?\(|\bmarshal\.loads?\(|"
         r"\bunserialize\s*\(|\bObjectInputStream\b|\bYaml\.load\(|"
         r"\bBinaryFormatter\b")),
    ("unsafe_exec", "high", "yaml.load without a safe loader",
     _rx(r"\byaml\.load\((?![^)]*(SafeLoader|safe_load))[^)]*\)")),
    ("unsafe_exec", "medium", "HTML written from a string",
     _rx(r"\.innerHTML\s*[+]?=|\bdangerouslySetInnerHTML\b|\bdocument\.write\s*\(|"
         r"\|\s*safe\b|\bmark_safe\s*\(|v-html=")),
]

_WEAK_CONTROL_RULES = [
    ("TLS certificate checking turned off",
     _rx(r"\bverify\s*=\s*False\b|\brejectUnauthorized\s*:\s*false\b|"
         r"\bInsecureSkipVerify\s*:\s*true\b|\bssl\.CERT_NONE\b|\bCERT_NONE\b|"
         r"\bcheck_hostname\s*=\s*False\b|_create_unverified_context|"
         r"NODE_TLS_REJECT_UNAUTHORIZED['\"]?\s*[=:]\s*['\"]?0|"
         r"\bverify_ssl\s*[:=]\s*(false|False)\b|\bstrict-ssl\s*[=\s]\s*false\b|"
         r"\bCURLOPT_SSL_VERIFYPEER\s*,\s*(false|0)\b|\bTrustAllCerts\b|"
         r"\bsslmode\s*=\s*disable\b")),
    ("signature or token verification turned off",
     _rx(r"algorithms?\s*[=:]\s*\[?\s*[\"']none[\"']|\bverify_signature[\"']?\s*[:=]\s*(False|false)\b|"
         r"\bverify_(exp|aud|iss)[\"']?\s*[:=]\s*(False|false)\b|"
         r"\bignoreExpiration\s*:\s*true\b|\balg(orithm)?\s*[:=]\s*[\"']none[\"']", re.I)),
    ("CSRF protection turned off",
     _rx(r"@csrf_exempt\b|\bcsrf\w*\s*[:=]\s*(False|false)\b|csrf\(\)\s*\.disable\(|"
         r"\bcsrf\.disable\(|\bskip_before_action\s*:verify_authenticity_token|"
         r"\bprotect_from_forgery\b.*\bnull_session\b|\bWTF_CSRF_ENABLED\s*=\s*False", re.I)),
    ("any origin or host allowed",
     _rx(r"\bALLOWED_HOSTS\s*=\s*\[\s*[\"']\*|\ballow_origins\s*=\s*\[\s*[\"']\*|"
         r"Access-Control-Allow-Origin[\"']?\s*[:,=]\s*[\"']?\*|"
         r"\borigin\s*:\s*[\"']\*[\"']|\bCORS_ALLOW_ALL_ORIGINS\s*=\s*True|"
         r"\bcors\(\s*\)", re.I)),
    ("authentication switched off",
     _rx(r"\bpermitAll\(\)|\bauth(entication)?[_.]?(required|enabled)\s*[:=]\s*(False|false|0)\b|"
         r"\bDEBUG\s*=\s*True\b|\bAUTH_DISABLED\b|\bdisable_?auth\w*\s*[:=]\s*(True|true|1)\b|"
         r"\bskip_?auth\w*\s*[:=]\s*(True|true|1)\b|\bgit\s+(commit|push)\b.*--no-verify|"
         r"\bSECURE_SSL_REDIRECT\s*=\s*False\b|\bSESSION_COOKIE_SECURE\s*=\s*False\b|"
         r"\bhttpOnly\s*:\s*false\b|\bsecure\s*:\s*false\b", re.I)),
]

_CRYPTO_RULES = [
    ("weak hash (MD5/SHA-1)",
     _rx(r"\bhashlib\.(md5|sha1)\((?![^)]*usedforsecurity\s*=\s*False)|"
         r"MessageDigest\.getInstance\(\s*[\"'](MD5|SHA-?1)[\"']|"
         r"createHash\(\s*[\"'](md5|sha1)[\"']|\bMD5\.Create\(|\bSHA1\.Create\(|"
         r"(?<!usedforsecurity)\bmd5\s*\(\s*[\$\w\"'](?![^)]*usedforsecurity\s*=\s*False)|"
         r"\bsha1\s*\(\s*[\$\w\"'](?![^)]*usedforsecurity\s*=\s*False)|\bDigest::(MD5|SHA1)\b", re.I)),
    ("broken cipher or mode",
     _rx(r"\bMODE_ECB\b|AES/ECB|\bDES\b(?!\w)|\bDES3\b|\bRC4\b|\bARC4\b|"
         r"createCipher\(|\bBlowfish\b|\bBF-\w+", 0)),
    ("non-cryptographic randomness for a secret",
     _rx(r"(Math\.random\(\)|\brandom\.(random|randint|choice|choices)\(|\brand\(\)|\bmt_rand\()"
         r".*(token|secret|password|passwd|session|nonce|salt|otp|apikey|api_key)|"
         r"(token|secret|password|passwd|session|nonce|salt|otp|apikey|api_key).*"
         r"(Math\.random\(\)|\brandom\.(random|randint|choice|choices)\(|\bmt_rand\()", re.I)),
    ("hard-coded IV or salt",
     _rx(r"\b(iv|nonce|salt)\s*=\s*b?[\"'][A-Za-z0-9+/=]{8,}[\"']", re.I)),
]

_PERMISSION_RULES = [
    ("world-writable or setuid permissions",
     _rx(r"\bchmod\s+(-R\s+)?(0?777|0?666|a\+rwx|ugo\+rwx|[ug]\+s)\b|"
         r"os\.chmod\([^)]*0o?7[67]7\)|\bsetuid\b|\bFileMode\(0?777\)|0o?777\b")),
    ("privileged container or host access",
     _rx(r"\bprivileged\s*:\s*true\b|--privileged\b|\ballowPrivilegeEscalation\s*:\s*true\b|"
         r"\bhost(Network|PID|IPC)\s*:\s*true\b|\brunAsUser\s*:\s*0\b|"
         r"\bcap_add\b|\bSYS_ADMIN\b|\bsecurityContext\s*:\s*\{\s*\}|"
         r"/var/run/docker\.sock|\bnetwork_mode\s*:\s*[\"']?host\b")),
    ("wildcard in an access policy",
     _rx(r"[\"']?Action[\"']?\s*[:=]\s*\[?\s*[\"']\*[\"']|"
         r"[\"']?Principal[\"']?\s*[:=]\s*\{?\s*[\"']?\*[\"']?|"
         r"[\"']?Resource[\"']?\s*[:=]\s*\[?\s*[\"']\*[\"']|"
         r"\bactions\s*=\s*\[\s*[\"']\*[\"']|\bNOPASSWD\s*:\s*ALL\b|"
         r"\b(roles?/)?(owner|editor)\b.*\ballUsers\b|\ballUsers\b|\ballAuthenticatedUsers\b", re.I)),
    ("open to the whole internet",
     _rx(r"\b0\.0\.0\.0/0\b|::/0\b|\bpublicly_accessible\s*=\s*true\b|"
         r"\bacl\s*=\s*[\"']public-read(-write)?[\"']|\bpublic_access\s*[:=]\s*(true|True)\b", re.I)),
    ("runs as root",
     _rx(r"^\s*USER\s+(root|0)\b")),
    ("workflow token write access",
     _rx(r"^\s*permissions:\s*write-all\b|^\s*(contents|packages|id-token|actions|"
         r"pull-requests|issues|checks|deployments|security-events|statuses):\s*write\b")),
]

_REMOTE_SCRIPT = _rx(
    r"\b(curl|wget|fetch|iwr|Invoke-WebRequest)\b[^|;\n]*\|\s*(sudo\s+)?"
    r"(ba|z|da|k)?sh\b|\bbase64\s+(-d|--decode)\b[^|\n]*\|\s*(ba)?sh\b|"
    r"\b(iex|Invoke-Expression)\b.*(DownloadString|iwr|Invoke-WebRequest|curl)|"
    r"\bbash\s+<\(\s*(curl|wget)\b", re.I)

_MIGRATION_DESTRUCTIVE = _rx(
    r"\bDROP\s+(TABLE|COLUMN|DATABASE|SCHEMA|INDEX|CONSTRAINT)\b|\bTRUNCATE\b|"
    r"\bDELETE\s+FROM\s+\w+\s*;|\bALTER\s+TABLE\b.*\bDROP\b|\bRemoveField\b|\bDeleteModel\b|"
    r"\bop\.drop_(table|column|constraint)\b|\bdrop_table\b|\bremove_column\b|\bdropTable\b|"
    r"\bdropColumn\b|\bRunSQL\b.*\bDROP\b", re.I)

#: guards: what a removed line must contain to count as an auth/validation check
_GUARD = _rx(
    r"\b(login_required|permission_required|user_passes_test|requires?_(auth|login|role|permission)\w*|"
    r"PreAuthorize|PostAuthorize|Secured|RolesAllowed|authenticated|authorize\w*|authenticate\w*|"
    r"check_permission\w*|has_permission\w*|is_authenticated|is_admin|is_staff|\w*csrf\w*|"
    r"verify_signature|verify_token|validate_token|rate_?limit\w*|throttle\w*|sanitize\w*|"
    r"escape_?html|html_escape|parameterized|prepare\(|requireAuth|ensureLoggedIn|"
    r"hasRole|hasAuthority|checkAccess|can_access|verifyJwt|jwt\.verify)\b", re.I)

_TEST_WEAK_ADD = _rx(
    r"@pytest\.mark\.(skip|xfail)\b|\bpytest\.(skip|xfail)\(|\bunittest\.(skip|expectedFailure)\b|"
    r"@(unittest\.)?skip\b|(?<![\w.])(xit|xdescribe|xtest)\s*\(|\b(it|test|describe)\.(skip|only|todo)\b|"
    r"@Ignore\b|@Disabled\b|\bt\.Skip(Now)?\(|\bassert\s+(True|1)\s*$|\bexpect\(\s*true\s*\)\.toBe\(\s*true\s*\)|"
    r"\bassertTrue\(\s*True\s*\)|\bcontinue-on-error:\s*true\b|\|\|\s*true\b|\bpass\s*#\s*TODO")
_ASSERT = _rx(r"\bassert\w*\b|\bexpect\s*\(|\.should\b|\bt\.(Error|Fatal)f?\(")

_NPM_SCRIPT = _rx(
    r"^\s*[\"'](preinstall|install|postinstall|prepare|prepack|postpack|prepublish(Only)?|"
    r"preuninstall|postuninstall)[\"']\s*:")
_PY_INSTALL = _rx(r"\bcmdclass\b|\bos\.system\b|\bsubprocess\b|\burlopen\b|\bexec\(|\beval\(|\bbase64\b")

_WF_PRT = _rx(r"\bpull_request_target\b")
_WF_HEAD_CHECKOUT = _rx(
    r"ref:\s*[\"']?\$\{\{\s*(github\.event\.pull_request\.head\.(sha|ref)|github\.head_ref|"
    r"github\.event\.workflow_run\.head_(sha|branch)|steps\.[\w.-]+\.outputs\.[\w-]*(sha|ref))")
_WF_UNTRUSTED = _rx(
    r"\$\{\{\s*(github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.(ref|label|repo\.full_name))|"
    r"comment\.body|review\.body|review_comment\.body|discussion\.(title|body)|"
    r"head_commit\.(message|author\.(email|name))|commits\[?[^}]*\.(message|author)|pages\[?[^}]*\.page_name|"
    r"workflow_run\.(head_branch|head_commit\.message|display_title))|"
    r"github\.head_ref|inputs\.[\w-]+)\s*\}\}")
_WF_ASSIGNMENT = _rx(r"^\s*[A-Za-z_][\w-]*:\s*[\"']?\$\{\{")
_WF_SAFE_KEYS = _rx(r"^\s*(if|name|group|cancel-in-progress|ref|repository|path|token):")
_WF_USES = _rx(r"^\s*-?\s*uses:\s*[\"']?([\w.-]+/[\w./-]+)@([^\s\"'#]+)")
_SHA40 = _rx(r"^[0-9a-f]{40}$")
_WF_SELF_HOSTED = _rx(r"runs-on:.*self-hosted")
_WF_SECRETS_INHERIT = _rx(r"\bsecrets:\s*inherit\b")

_REGISTRY_OK = ("registry.npmjs.org", "registry.yarnpkg.com", "pypi.org",
                "files.pythonhosted.org", "proxy.golang.org", "rubygems.org",
                "crates.io", "static.crates.io", "repo.maven.apache.org",
                "repo1.maven.org", "plugins.gradle.org", "nuget.org",
                "api.nuget.org", "packagist.org", "repo.packagist.org")
_URL_HOST = _rx(r"(?:https?|git\+https?|git\+ssh|ssh|git)://(?:[^@/\s\"']*@)?([^/:\s\"']+)", re.I)
_DEP_SOURCE_BAD = _rx(
    r"git\+(ssh|https?|git)://|\"(github|gitlab|bitbucket):|[\"']git(hub)?://|"
    r"\bgit\s*=\s*[\"']|\bpath\s*=\s*[\"']\.\.|^\s*-e\s+(git|http)|@\s*git\+|"
    r"--(extra-)?index-url|--trusted-host|--find-links|\bfile:\.\./|\breplace\s+\S+\s+=>", re.I)

_ENTROPY_MIN = 3.2
_PLACEHOLDER = _rx(
    r"(example|sample|changeme|change[-_]?me|dummy|placeholder|your[-_]|<[^>]+>|xxxx|\*{4}|"
    r"redacted|fake|todo|replace[-_]?me|\$\{|\{\{|%\(|\bnull\b|\bnone\b|process\.env|os\.environ|"
    r"getenv|env\[|secrets\.|insert[-_]|foobar|password123|test[-_]?(key|token|secret))", re.I)

_SECRET_RULES = [
    ("cloud access key id", _rx(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("GitHub token", _rx(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{50,}\b")),
    ("Slack token", _rx(r"\bxox[baprs]-[A-Za-z0-9-]{10,}")),
    ("payment live key", _rx(r"\b[sr]k_live_[A-Za-z0-9]{16,}")),
    ("Google API key", _rx(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("LLM provider key", _rx(r"\bsk-ant-[A-Za-z0-9_\-]{20,}|\bsk-(proj-)?[A-Za-z0-9_\-]{40,}")),
    ("private key block", _rx(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY( BLOCK)?-----")),
    ("signed token (JWT)", _rx(r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("credentials in a URL", _rx(r"\b[a-z][a-z0-9+.-]*://[^\s/:@\"']{2,}:[^\s/@\"']{6,}@[\w.-]+")),
]
_MAYBE_SECRET = _rx(r"key|secret|token|pass|pwd|auth", re.I)
_GENERIC_SECRET = _rx(
    r"(api[_-]?key|secret|token|passw(or)?d|pwd|auth[_-]?key|private[_-]?key|access[_-]?key|client[_-]?secret)"
    r"[\w\-]*[\"']?\s*[:=]\s*[\"']([^\"'\s]{12,})[\"']", re.I)


_Q_CODE = _Quick(["eval", "exec", "function", "system", "popen", "passthru", "shell",
                  "pickle", "marshal", "unserialize", "objectinput", "yaml",
                  "binaryformatter", "innerhtml", "dangerously", "document.write",
                  "safe", "v-html", "child_process", "query", "raw", "prepare", "proc_open", "__import__", "getattr"])
_Q_WEAK = _Quick(["verif", "unauthorized", "insecure", "cert_none", "check_hostname",
                  "unverified", "tls_reject", "ssl", "trustall", "algorithm", "alg",
                  "expiration", "csrf", "forgery", "allowed_hosts", "origin", "cors",
                  "permitall", "auth", "debug", "no-verify", "secure", "httponly"])
_Q_CRYPTO = _Quick(["md5", "sha1", "sha-1", "ecb", "des", "rc4", "createcipher",
                    "blowfish", "bf-", "rand", "iv", "nonce", "salt"])
_Q_PERM = _Quick(["chmod", "setuid", "filemode", "777", "666", "rwx", "privilege", "host",
                  "runasuser", "cap_add", "sys_admin", "securitycontext", "docker.sock",
                  "network_mode", "action", "principal", "resource", "nopasswd",
                  "allusers", "allauthenticated", "0.0.0.0", "::/0", "publicly", "acl",
                  "public_access", "user", "permissions", "write", "owner", "editor"])
_Q_SECRET = _Quick(["AKIA", "ASIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_",
                    "xox", "k_live_", "AIza", "sk-", "-----BEGIN", "eyJ", "://"], raw=True)
_Q_TESTWEAK = _Quick(["skip", "xfail", "expectedfailure", "xit(", "xdescribe", "xtest",
                      ".only", ".todo", "@ignore", "@disabled", "assert true", "assert 1",
                      "expect(true", "asserttrue(", "continue-on-error", "|| true", "todo"])


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    n = len(s)
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _is_comment(line: str) -> bool:
    return bool(_COMMENT_START.match(line))


# --- the scan ------------------------------------------------------------------

class _Out:
    """Collects every finding, then keeps the most severe ones within the
    caps. (Capping in scan order let a file of 40 harmless findings push a
    secret on line 100 out of the report and the score.)"""

    def __init__(self):
        self.items: list[Finding] = []
        self.dropped = 0
        self.seen: set[tuple] = set()
        self.budget = MAX_LINES_TOTAL

    def add(self, cls, sev, file, line, why):
        key = (cls, file, line, why)
        if key in self.seen:
            return
        self.seen.add(key)
        self.items.append(Finding(cls, sev, file, line, why))

    def capped(self) -> list[Finding]:
        rank = lambda f: (SEVERITY_ORDER.index(f.severity), f.file, f.line, f.cls)  # noqa: E731
        per: dict[str, int] = {}
        kept: list[Finding] = []
        for f in sorted(self.items, key=rank):
            if per.get(f.file, 0) >= MAX_PER_FILE or len(kept) >= MAX_TOTAL:
                self.dropped += 1
                continue
            per[f.file] = per.get(f.file, 0) + 1
            kept.append(f)
        return kept


def _units(lines: dict[int, str], out: "_Out", rel: str, on_limit: bool):
    """(line number, text to search, first window of that line) for each
    added line, long lines as overlapping windows. Past the limits, a
    `scan_limit` finding says how much was not searched."""
    windows = 0
    skipped_lines = 0
    cut_line = 0
    step = MAX_LINE_CHARS - WINDOW_OVERLAP
    allowed = min(MAX_LINES_PER_FILE, out.budget)
    out.budget -= min(allowed, len(lines))
    for count, n in enumerate(sorted(lines), 1):
        if count > allowed:
            skipped_lines = len(lines) - allowed
            break
        t = lines[n]
        if len(t) <= MAX_LINE_CHARS:
            yield n, t, t
            continue
        first = t[:MAX_LINE_CHARS]
        for k, start in enumerate(range(0, len(t), step)):
            if k >= MAX_WINDOWS_PER_LINE or windows >= MAX_WINDOWS_PER_FILE:
                cut_line = cut_line or n
                break
            windows += 1
            yield n, t[start:start + MAX_LINE_CHARS], first
            if start + MAX_LINE_CHARS >= len(t):
                break
    if on_limit:
        if skipped_lines:
            out.add("scan_limit", "medium", rel, 0,
                    f"{skipped_lines} added line(s) were not searched (limits: {MAX_LINES_PER_FILE} per file, {MAX_LINES_TOTAL} per run)")
        if cut_line:
            out.add("scan_limit", "medium", rel, cut_line,
                    "a very long line was only searched in part (minified or padded to hide text)")


def scan(added: dict[str, dict[int, str]],
         removed: dict[str, list[str]] | None = None,
         deleted: list[str] | None = None,
         ignore_paths: list[str] = (), off: list[str] = ()
         ) -> tuple[list[Finding], int]:
    """(findings, how many were left out for the caps) of a diff.

    added   file -> {line number: text}
    removed file -> [text of each removed line]
    deleted whole files that are gone
    ignore_paths: globs whose files are not searched (vendored, generated)
    off     class names to skip"""
    removed = removed or {}
    out = _Out()
    files = sorted(set(added) | set(removed) | set(deleted or []))
    changed = {_norm(f) for f in files}
    ign = [g.casefold() for g in ignore_paths]
    on = lambda c: c not in off  # noqa: E731
    u_exec, w_ctl, w_cry = on("unsafe_exec"), on("weak_control"), on("weak_crypto")

    for rel in files:
        path = _norm(rel)
        low = path.casefold()
        if any(fnmatch.fnmatchcase(low, g) or fnmatch.fnmatchcase("/" + low, g)
               or fnmatch.fnmatchcase(low.rsplit("/", 1)[-1], g) for g in ign):
            continue
        lines = added.get(rel, {})
        gone = removed.get(rel, [])
        is_wf = bool(_WORKFLOW.search(path))
        is_lock = bool(_LOCKFILE.search(path))
        is_manifest = bool(_MANIFEST.search(path))
        is_test = bool(_TEST.search(path))
        is_doc = bool(_DOC.search(path))
        is_mig = bool(_MIGRATION.search(path))
        is_iac = bool(_IAC.search(path))
        is_code = bool(_CODE.search(path))
        base_name = path.rsplit("/", 1)[-1]

        # file-level findings --------------------------------------------------
        if on("hidden_text"):
            for kind, detail in hidden.hidden_chars(rel):
                out.add("hidden_text", "critical" if kind in ("bidi", "tag_chars") else "high",
                        rel, 0, f"the file name contains {detail}")
        if is_wf and on("ci_workflow"):
            out.add("ci_workflow", "medium", rel, 0, "CI configuration changed")
        if is_lock and on("dependency"):
            twin = any(_MANIFEST.search(c) and c.rsplit("/", 1)[0] == path.rsplit("/", 1)[0]
                       for c in changed) or any(_MANIFEST.search(c) for c in changed)
            if twin:
                out.add("dependency", "medium", rel, 0, "lockfile changed with its manifest")
            else:
                out.add("dependency", "high", rel, 0,
                        "lockfile changed and no manifest did: versions moved without a declared reason")
        elif is_manifest and on("dependency"):
            out.add("dependency", "low", rel, 0, "dependency manifest changed")
        if is_iac and on("iac"):
            out.add("iac", "medium", rel, 0, "infrastructure definition changed")
        if on("secret") and _SECRET_FILE.search(path) and not _SECRET_FILE_OK.search(path):
            if lines or rel in (deleted or []):
                if lines:
                    out.add("secret", "high", rel, 0, "a file that normally holds credentials is committed")
        if on("install_script"):
            if re.search(r"\.pth$", base_name, re.I) and lines:
                out.add("install_script", "high", rel, 0, ".pth file: code runs at every Python start")
            if base_name.lower() in ("sitecustomize.py", "usercustomize.py") and lines:
                out.add("install_script", "high", rel, 0, "runs at every Python start")
            if base_name.lower() == ".npmrc" and lines:
                out.add("install_script", "medium", rel, 0, ".npmrc changed: registry and script settings")
            if re.search(r"(^|/)(\.husky|\.githooks|\.git-hooks)/|(^|/)\.pre-commit-config\.ya?ml$", path) and lines:
                out.add("install_script", "medium", rel, 0, "git hook configuration changed")

        # test deletion ----------------------------------------------------------
        if rel in (deleted or []) and is_test and on("test_weakening"):
            out.add("test_weakening", "medium", rel, 0, "a test file is deleted")

        # added lines -------------------------------------------------------------
        head_checkout = False
        prt_line = 0
        if is_wf:
            for n, t in lines.items():
                if _WF_HEAD_CHECKOUT.search(t[:MAX_LINE_CHARS]):
                    head_checkout = True
        for n, t, first_t in _units(lines, out, rel, on("scan_limit")):
            if not t.strip():
                continue
            low_t = t.lower()

            if on("hidden_text"):
                for kind, detail in hidden.hidden_chars(t, first_line=(n == 1)):
                    sev = "critical" if kind in ("bidi", "tag_chars") else "high"
                    out.add("hidden_text", sev, rel, n,
                            {"bidi": "bidirectional control character",
                             "tag_chars": "Unicode tag character (invisible ASCII)",
                             "invisible": "invisible character"}[kind] + f" {detail}")
                if not t.isascii() and not is_lock:
                    for _, detail in hidden.homoglyph_words(t):
                        out.add("hidden_text", "medium", rel, n, "look-alike letters: " + detail)
            if on("prompt_injection") and not is_lock:
                for _, why in hidden.injection_phrases(t):
                    out.add("prompt_injection", "high", rel, n, "text that " + why)

            if on("secret") and not is_lock:
                hit = False
                for why, rx in (_SECRET_RULES if _Q_SECRET(t, low_t) else ()):
                    if rx.search(t) and not _PLACEHOLDER.search(t):
                        out.add("secret", "critical", rel, n, why)
                        hit = True
                        break
                if not hit and not is_doc and _MAYBE_SECRET.search(t):
                    m = _GENERIC_SECRET.search(t)
                    if m:
                        val = m.group(3)
                        if (not _PLACEHOLDER.search(t) and _entropy(val) >= _ENTROPY_MIN
                                and not val.startswith(("http", "/", ".")) and not val.isalpha()):
                            out.add("secret", "high", rel, n, "assignment of a high-entropy string to a secret-like name")

            if is_lock:
                if on("dependency"):
                    for m in _URL_HOST.finditer(t):
                        host = m.group(1).lower()
                        if not any(host == h or host.endswith("." + h) for h in _REGISTRY_OK):
                            out.add("dependency", "high", rel, n,
                                    f"lockfile resolves a package from {host[:60]}, not a public registry")
                            break
                    else:
                        if re.search(r"\"resolved\":\s*\"(git|github:|file:)|git\+", t):
                            out.add("dependency", "high", rel, n, "lockfile resolves a package from git or a file")
                continue

            if is_wf and on("ci_workflow"):
                if _WF_PRT.search(t) and not _is_comment(t):
                    prt_line = prt_line or n
                if _WF_UNTRUSTED.search(t) and not _WF_ASSIGNMENT.match(t) \
                        and not _WF_SAFE_KEYS.match(t) and not _is_comment(t):
                    out.add("ci_workflow", "high", rel, n,
                            "attacker-controlled text interpolated into a script (workflow injection)")
                m = _WF_USES.match(t)
                if m and not m.group(1).startswith("./"):
                    if not _SHA40.match(m.group(2)):
                        owner = m.group(1).split("/", 1)[0].lower()
                        first_party = owner in ("actions", "github")
                        out.add("ci_workflow", "low" if first_party else "medium", rel, n,
                                f"{m.group(1)}@{m.group(2)[:20]} is not pinned to a commit")
                if _WF_SELF_HOSTED.search(t):
                    out.add("ci_workflow", "medium", rel, n, "runs on a self-hosted runner")
                if _WF_SECRETS_INHERIT.search(t):
                    out.add("ci_workflow", "medium", rel, n, "passes every secret to a called workflow")

            if is_manifest and on("dependency") and _DEP_SOURCE_BAD.search(t) and not _is_comment(t):
                out.add("dependency", "high", rel, n,
                        "dependency from git, a local path, another index or a replace directive")

            if on("install_script"):
                if base_name == "package.json" and _NPM_SCRIPT.match(t):
                    out.add("install_script", "high", rel, n, "npm lifecycle script runs at install time")
                if base_name in ("setup.py", "setup.cfg") and _PY_INSTALL.search(t) and not _is_comment(t):
                    out.add("install_script", "high", rel, n, "setup script runs arbitrary code at install time")

            if on("remote_script") and _REMOTE_SCRIPT.search(t):
                out.add("remote_script", "high", rel, n, "downloads a script and runs it unseen")

            comment = _is_comment(first_t)
            if is_doc or comment:
                continue

            if on("permissions") and _Q_PERM(t, low_t):
                for why, rx in _PERMISSION_RULES:
                    if rx.search(t):
                        if why == "workflow token write access" and not is_wf:
                            continue
                        if why == "runs as root" and not (is_iac or "dockerfile" in low):
                            continue
                        if why == "open to the whole internet" and not (is_iac or is_wf or path.endswith((".yaml", ".yml", ".json", ".tf"))):
                            continue
                        sev = "medium" if why in ("runs as root", "workflow token write access") else "high"
                        out.add("permissions", sev, rel, n, why)
                        break

            if is_test:
                if on("test_weakening") and _Q_TESTWEAK(t, low_t) and _TEST_WEAK_ADD.search(t):
                    out.add("test_weakening", "medium", rel, n, "a test is skipped, disabled or made trivial")
                continue
            if is_wf and on("test_weakening") and _TEST_WEAK_ADD.search(t):
                out.add("test_weakening", "medium", rel, n, "a CI failure is swallowed")

            if (is_code or is_wf or is_iac or is_manifest) and u_exec and _Q_CODE(t, low_t):
                for cls, sev, why, rx in _CODE_RULES:
                    if rx.search(t):
                        out.add(cls, sev, rel, n, why)
                        break
            if (is_code or is_wf or is_iac or path.endswith((".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf", ".env"))):
                if w_ctl and _Q_WEAK(t, low_t):
                    for why, rx in _WEAK_CONTROL_RULES:
                        if rx.search(t):
                            out.add("weak_control", "high", rel, n, why)
                            break
            if is_code and w_cry and _Q_CRYPTO(t, low_t):
                for why, rx in _CRYPTO_RULES:
                    if rx.search(t):
                        out.add("weak_crypto", "medium", rel, n, why)
                        break
            if (is_mig or is_code) and on("destructive_migration") and _MIGRATION_DESTRUCTIVE.search(t):
                if is_mig:
                    out.add("destructive_migration", "high", rel, n, "migration drops or empties data")

        if prt_line and on("ci_workflow"):
            if head_checkout:
                out.add("ci_workflow", "critical", rel, prt_line,
                        "pull_request_target checks out the pull request's own code: a fork runs with the repository's secrets")
            else:
                out.add("ci_workflow", "high", rel, prt_line,
                        "pull_request_target runs with write access and secrets on fork pull requests")

        # removed lines -----------------------------------------------------------
        if gone and not is_doc and not is_lock:
            if on("guard_removed") and not is_test and (is_code or is_wf):
                took = {m.group(1).lower() for t in gone[:MAX_LINES_PER_FILE]
                        if not _is_comment(t[:MAX_LINE_CHARS])
                        for m in [_GUARD.search(t[:MAX_LINE_CHARS])] if m}
                kept = {m.group(1).lower() for t in lines.values()
                        for m in [_GUARD.search(t[:MAX_LINE_CHARS])] if m}
                for tok in sorted(took - kept)[:3]:
                    out.add("guard_removed", "medium", rel, 0,
                            f"a line using `{tok[:40]}` is removed and nothing in the file replaces it")
            if on("test_weakening") and is_test:
                n_gone = sum(1 for t in gone if _ASSERT.search(t[:MAX_LINE_CHARS]))
                n_new = sum(1 for t in lines.values() if _ASSERT.search(t[:MAX_LINE_CHARS]))
                if n_gone >= 3 and n_gone >= n_new + 3:
                    out.add("test_weakening", "medium", rel, 0,
                            f"{n_gone} assertion lines removed, {n_new} added")
            if is_wf and on("test_weakening"):
                for t in gone:
                    if re.search(r"\b(pytest|npm (run )?test|cargo test|go test|mvn test|gradle test|"
                                 r"yarn test|tox|semgrep|bandit|codeql|trivy|snyk|audit)\b", t[:MAX_LINE_CHARS]) \
                            and not _is_comment(t):
                        out.add("test_weakening", "medium", rel, 0,
                                "a test or security-scan step is removed from CI")
                        break
    kept = out.capped()
    return kept, out.dropped


def points(findings: list[Finding]) -> tuple[int, dict[str, str]]:
    """(points, class -> highest severity) of findings, capped."""
    top: dict[str, str] = {}
    for f in findings:
        cur = top.get(f.cls)
        if cur is None or SEVERITY_ORDER.index(f.severity) < SEVERITY_ORDER.index(cur):
            top[f.cls] = f.severity
    return min(MAX_POINTS, sum(SEVERITY_POINTS[s] for s in top.values())), top
