# -*- coding: utf-8 -*-
from __future__ import unicode_literals

issues_data = {
     "B101": {
    "severity": "LOW",
    "description": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
    "categories": [],
    "title": "assert_used"
  },
  "B104": {
    "severity": "MEDIUM",
    "description": "Possible binding to all interfaces.",
    "categories": [],
    "title": "hardcoded_bind_all_interfaces"
  },
  "B305": {
    "severity": "MEDIUM",
    "description": "Use of insecure cipher mode cryptography.hazmat.primitives.ciphers.modes.ECB.",
    "categories": [],
    "title": "blacklist"
  },
  "B413": {
    "severity": "HIGH",
    "description": "The pyCrypto library and its module RSA are no longer actively maintained and have been deprecated. Consider using pyca/cryptography library.",
    "categories": [],
    "title": "blacklist"
  },
  "B414": {
    "severity": "HIGH",
    "description": "The pycryptodome library is not considered a secure alternative to pycrypto.Consider using pyca/cryptography library.",
    "categories": [],
    "title": "blacklist"
  },
  "B304": {
    "severity": "HIGH",
    "description": "Use of insecure cipher cryptography.hazmat.primitives.ciphers.algorithms.IDEA. Replace with a known secure cipher such as AES.",
    "categories": [],
    "title": "blacklist"
  },
  "B303": {
    "severity": "MEDIUM",
    "description": "Use of insecure MD2, MD4, MD5, or SHA1 hash function.",
    "categories": [],
    "title": "blacklist"
  },
  "B610": {
    "severity": "MEDIUM",
    "description": "Use of extra potential SQL attack vector.",
    "categories": [],
    "title": "django_extra_used"
  },
  "B611": {
    "severity": "MEDIUM",
    "description": "Use of RawSQL potential SQL attack vector.",
    "categories": [],
    "title": "django_rawsql_used"
  },
  "B307": {
    "severity": "MEDIUM",
    "description": "Use of possibly insecure function - consider using safer ast.literal_eval.",
    "categories": [],
    "title": "blacklist"
  },
  "B102": {
    "severity": "MEDIUM",
    "description": "Use of exec detected.",
    "categories": [],
    "title": "exec_used"
  },
  "B201": {
    "severity": "HIGH",
    "description": "A Flask app appears to be run with debug=True, which exposes the Werkzeug debugger and allows the execution of arbitrary code.",
    "categories": [],
    "title": "flask_debug_true"
  },
  "B402": {
    "severity": "HIGH",
    "description": "A FTP-related module is being imported.  FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.",
    "categories": [],
    "title": "blacklist"
  },
  "B321": {
    "severity": "HIGH",
    "description": "FTP-related functions are being called. FTP is considered insecure. Use SSH/SFTP/SCP or some other encrypted protocol.",
    "categories": [],
    "title": "blacklist"
  },
  "B107": {
    "severity": "LOW",
    "description": "Possible hardcoded password: 'blerg'",
    "categories": [],
    "title": "hardcoded_password_default"
  },
  "B105": {
    "severity": "LOW",
    "description": "Possible hardcoded password: 'blerg'",
    "categories": [],
    "title": "hardcoded_password_string"
  },
  "B106": {
    "severity": "LOW",
    "description": "Possible hardcoded password: 'blerg'",
    "categories": [],
    "title": "hardcoded_password_funcarg"
  },
  "B108": {
    "severity": "MEDIUM",
    "description": "Probable insecure usage of temp file/directory.",
    "categories": [],
    "title": "hardcoded_tmp_directory"
  },
  "B324": {
    "severity": "MEDIUM",
    "description": "Use of insecure MD4 or MD5 hash function.",
    "categories": [],
    "title": "hashlib_new"
  },
  "B309": {
    "severity": "MEDIUM",
    "description": "Use of HTTPSConnection on older versions of Python prior to 2.7.9 and 3.4.3 do not provide security, see https://wiki.openstack.org/wiki/OSSN/OSSN-0033",
    "categories": [],
    "title": "blacklist"
  },
  "B412": {
    "severity": "HIGH",
    "description": "Consider possible security implications associated with twisted.web.twcgi.CGIScript module.",
    "categories": [],
    "title": "blacklist"
  },
  "B404": {
    "severity": "LOW",
    "description": "Consider possible security implications associated with subprocess module.",
    "categories": [],
    "title": "blacklist"
  },
  "B403": {
    "severity": "LOW",
    "description": "Consider possible security implications associated with pickle module.",
    "categories": [],
    "title": "blacklist"
  },
  "B602": {
    "severity": "LOW",
    "description": "subprocess call with shell=True seems safe, but may be changed in the future, consider rewriting without shell",
    "categories": [],
    "title": "subprocess_popen_with_shell_equals_true"
  },
  "B301": {
    "severity": "MEDIUM",
    "description": "Pickle library appears to be in use, possible security issue.",
    "categories": [],
    "title": "blacklist"
  },
  "B322": {
    "severity": "HIGH",
    "description": "The input method in Python 2 will read from standard input, evaluate and run the resulting string as python source code. This is similar, though in many ways worse, then using eval. On Python 2, use raw_input instead, input is safe in Python 3.",
    "categories": [],
    "title": "blacklist"
  },
  "B701": {
    "severity": "HIGH",
    "description": "Using jinja2 templates with autoescape=False is dangerous and can lead to XSS. Ensure autoescape=True or use the select_autoescape function to mitigate XSS vulnerabilities.",
    "categories": [],
    "title": "jinja2_autoescape_false"
  },
  "B702": {
    "severity": "MEDIUM",
    "description": "Mako templates allow HTML/JS rendering by default and are inherently open to XSS attacks. Ensure variables in all templates are properly sanitized via the 'n', 'h' or 'x' flags (depending on context). For example, to HTML escape the variable 'data' do ${ data |h }.",
    "categories": [],
    "title": "use_of_mako_templates"
  },
  "B308": {
    "severity": "MEDIUM",
    "description": "Use of mark_safe() may expose cross-site scripting vulnerabilities and should be reviewed.",
    "categories": [],
    "title": "blacklist"
  },
  "B703": {
    "severity": "MEDIUM",
    "description": "Potential XSS on mark_safe function.",
    "categories": [],
    "title": "django_mark_safe"
  },
  "B302": {
    "severity": "MEDIUM",
    "description": "Deserialization with the marshal module is possibly dangerous.",
    "categories": [],
    "title": "blacklist"
  },
  "B306": {
    "severity": "MEDIUM",
    "description": "Use of insecure and deprecated function (mktemp).",
    "categories": [],
    "title": "blacklist"
  },
  "B506": {
    "severity": "MEDIUM",
    "description": "Use of unsafe yaml load. Allows instantiation of arbitrary objects. Consider yaml.safe_load().",
    "categories": [],
    "title": "yaml_load"
  },
  "B317": {
    "severity": "MEDIUM",
    "description": "Using xml.sax.make_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.make_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
    "categories": [],
    "title": "blacklist"
  },
  "B103": {
    "severity": "HIGH",
    "description": "Chmod setting a permissive mask 0777 on file (key_file).",
    "categories": [],
    "title": "set_bad_file_permissions"
  },
  "B606": {
    "severity": "LOW",
    "description": "Starting a process without a shell.",
    "categories": [],
    "title": "start_process_with_no_shell"
  },
  "B605": {
    "severity": "LOW",
    "description": "Starting a process with a shell: Seems safe, but may be changed in the future, consider rewriting without shell",
    "categories": [],
    "title": "start_process_with_a_shell"
  },
  "B601": {
    "severity": "MEDIUM",
    "description": "Possible shell injection via Paramiko call, check inputs are properly sanitized.",
    "categories": [],
    "title": "paramiko_calls"
  },
  "B603": {
    "severity": "LOW",
    "description": "subprocess call - check for execution of untrusted input.",
    "categories": [],
    "title": "subprocess_without_shell_equals_true"
  },
  "B607": {
    "severity": "LOW",
    "description": "Starting a process with a partial executable path",
    "categories": [],
    "title": "start_process_with_partial_path"
  },
  "B311": {
    "severity": "LOW",
    "description": "Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
    "categories": [],
    "title": "blacklist"
  },
  "B501": {
    "severity": "HIGH",
    "description": "Requests call with verify=False disabling SSL certificate checks, security issue.",
    "categories": [],
    "title": "request_with_no_cert_validation"
  },
  "B608": {
    "severity": "MEDIUM",
    "description": "Possible SQL injection vector through string-based query construction.",
    "categories": [],
    "title": "hardcoded_sql_expressions"
  },
  "B502": {
    "severity": "MEDIUM",
    "description": "Function call with insecure SSL/TLS protocol identified, possible security issue.",
    "categories": [],
    "title": "ssl_with_bad_version"
  },
  "B504": {
    "severity": "LOW",
    "description": "ssl.wrap_socket call with no SSL/TLS protocol version specified, the default SSLv23 could be insecure, possible security issue.",
    "categories": [],
    "title": "ssl_with_no_version"
  },
  "B503": {
    "severity": "MEDIUM",
    "description": "Function definition identified with insecure SSL/TLS protocol version by default, possible security issue.",
    "categories": [],
    "title": "ssl_with_bad_defaults"
  },
  "B604": {
    "severity": "MEDIUM",
    "description": "Function call with shell=True parameter identified, possible security issue.",
    "categories": [],
    "title": "any_other_function_with_shell_equals_true"
  },
  "B401": {
    "severity": "HIGH",
    "description": "A telnet-related module is being imported.  Telnet is considered insecure. Use SSH or some other encrypted protocol.",
    "categories": [],
    "title": "blacklist"
  },
  "B312": {
    "severity": "HIGH",
    "description": "Telnet-related functions are being called. Telnet is considered insecure. Use SSH or some other encrypted protocol.",
    "categories": [],
    "title": "blacklist"
  },
  "B325": {
    "severity": "MEDIUM",
    "description": "Use of os.tempnam() and os.tmpnam() is vulnerable to symlink attacks. Consider using tmpfile() instead.",
    "categories": [],
    "title": "blacklist"
  },
  "B112": {
    "severity": "LOW",
    "description": "Try, Except, Continue detected.",
    "categories": [],
    "title": "try_except_continue"
  },
  "B110": {
    "severity": "LOW",
    "description": "Try, Except, Pass detected.",
    "categories": [],
    "title": "try_except_pass"
  },
  "B323": {
    "severity": "MEDIUM",
    "description": "By default, Python will create a secure, verified ssl context for use in such classes as HTTPSConnection. However, it still allows using an insecure context via the _create_unverified_context that reverts to the previous behavior that does not validate certificates or perform hostname checks.",
    "categories": [],
    "title": "blacklist"
  },
  "B310": {
    "severity": "MEDIUM",
    "description": "Audit url open for permitted schemes. Allowing use of file:/ or custom schemes is often unexpected.",
    "categories": [],
    "title": "blacklist"
  },
  "B505": {
    "severity": "HIGH",
    "description": "RSA key sizes below 1024 bits are considered breakable. ",
    "categories": [],
    "title": "weak_cryptographic_key"
  },
  "B609": {
    "severity": "HIGH",
    "description": "Possible wildcard injection in call: subprocess.Popen",
    "categories": [],
    "title": "linux_commands_wildcard_injection"
  },
  "B405": {
    "severity": "LOW",
    "description": "Using xml.etree.ElementTree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
    "categories": [],
    "title": "blacklist"
  },
  "B313": {
    "severity": "MEDIUM",
    "description": "Using xml.etree.cElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.cElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
    "categories": [],
    "title": "blacklist"
  },
  "B314": {
    "severity": "MEDIUM",
    "description": "Using xml.etree.ElementTree.XMLParser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.etree.ElementTree.XMLParser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
    "categories": [],
    "title": "blacklist"
  },
  "B407": {
    "severity": "LOW",
    "description": "Using xml.dom.expatbuilder to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
    "categories": [],
    "title": "blacklist"
  },
  "B316": {
    "severity": "MEDIUM",
    "description": "Using xml.dom.expatbuilder.parseString to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.expatbuilder.parseString with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
    "categories": [],
    "title": "blacklist"
  },
  "B406": {
    "severity": "LOW",
    "description": "Using sax to parse untrusted XML data is known to be vulnerable to XML attacks. Replace sax with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
    "categories": [],
    "title": "blacklist"
  },
  "B315": {
    "severity": "MEDIUM",
    "description": "Using xml.sax.expatreader.create_parser to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.sax.expatreader.create_parser with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
    "categories": [],
    "title": "blacklist"
  },
  "B410": {
    "severity": "LOW",
    "description": "Using etree to parse untrusted XML data is known to be vulnerable to XML attacks. Replace etree with the equivalent defusedxml package.",
    "categories": [],
    "title": "blacklist"
  },
  "B320": {
    "severity": "MEDIUM",
    "description": "Using lxml.etree.fromstring to parse untrusted XML data is known to be vulnerable to XML attacks. Replace lxml.etree.fromstring with its defusedxml equivalent function.",
    "categories": [],
    "title": "blacklist"
  },
  "B408": {
    "severity": "LOW",
    "description": "Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
    "categories": [],
    "title": "blacklist"
  },
  "B318": {
    "severity": "MEDIUM",
    "description": "Using xml.dom.minidom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.minidom.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
    "categories": [],
    "title": "blacklist"
  },
  "B409": {
    "severity": "LOW",
    "description": "Using parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace parse with the equivalent defusedxml package, or make sure defusedxml.defuse_stdlib() is called.",
    "categories": [],
    "title": "blacklist"
  },
  "B319": {
    "severity": "MEDIUM",
    "description": "Using xml.dom.pulldom.parse to parse untrusted XML data is known to be vulnerable to XML attacks. Replace xml.dom.pulldom.parse with its defusedxml equivalent function or make sure defusedxml.defuse_stdlib() is called",
    "categories": [],
    "title": "blacklist"
  },
  "B411": {
    "severity": "HIGH",
    "description": "Using xmlrpclib to parse untrusted XML data is known to be vulnerable to XML attacks. Use defused.xmlrpc.monkey_patch() function to monkey-patch xmlrpclib and mitigate XML vulnerabilities.",
    "categories": [],
    "title": "blacklist"
  }

}
