import 'dart:convert';
import 'dart:typed_data';

/// The kind of content a pasted / scanned / received string holds.
///
/// Bettbox historically only accepted Clash subscription addresses, this makes
/// the import path behave like v2rayNG: anything that carries server
/// information (single share link, a bundle of share links, a base64 blob or a
/// raw YAML config) can be imported and is turned into a local profile.
enum ShareLinkContentKind {
  /// A regular `http(s)` / `ftp` subscription address.
  subscriptionUrl,

  /// One or more proxy share links (`vmess://`, `vless://`, `ss://`, ...).
  shareLink,

  /// A Clash / Mihomo YAML config, either raw or base64 wrapped.
  yamlConfig,

  /// Content that could not be recognized.
  unknown,
}

/// A single link that could not be converted into a proxy.
class ShareLinkFailure {
  const ShareLinkFailure({required this.link, required this.reason});

  final String link;
  final String reason;

  @override
  String toString() => reason;
}

/// The outcome of [ShareLink.parse].
class ShareLinkParseResult {
  const ShareLinkParseResult({
    this.kind = ShareLinkContentKind.unknown,
    this.proxies = const [],
    this.yaml,
    this.url,
    this.failures = const [],
    this.linkCount = 0,
  });

  /// What the source text turned out to be.
  final ShareLinkContentKind kind;

  /// Parsed Mihomo proxy mappings, in source order.
  final List<Map<String, Object?>> proxies;

  /// Ready to save config text when the source already was a config.
  final String? yaml;

  /// The subscription address when the source was a plain URL.
  final String? url;

  /// Links that were recognized but rejected, with the reason.
  final List<ShareLinkFailure> failures;

  /// How many share links were found in the source text.
  final int linkCount;

  /// Whether something importable came out of the source text.
  bool get hasContent => proxies.isNotEmpty || yaml != null;

  /// How many of the found links were dropped.
  int get failureCount => failures.length;

  /// Names of all parsed proxies.
  List<String> get proxyNames =>
      proxies.map((proxy) => '${proxy['name']}').toList();
}

/// Parsed pieces of a `scheme://user@host:port?query#fragment` share link.
class _LinkParts {
  const _LinkParts({
    required this.scheme,
    required this.userInfo,
    required this.host,
    required this.port,
    required this.query,
    required this.fragment,
    this.portRange,
  });

  final String scheme;
  final String userInfo;
  final String host;
  final int? port;

  /// Port hopping range (`20000-30000`), used by the hysteria family.
  final String? portRange;

  /// Query parameters with normalized (lower case, separator free) keys.
  final Map<String, String> query;
  final String fragment;

  String? param(List<String> keys) {
    for (final key in keys) {
      final value = query[_normalizeKey(key)];
      if (value != null && value.isNotEmpty) return value;
    }
    return null;
  }

  bool? flag(List<String> keys) => _boolValue(param(keys));
}

String _normalizeKey(String key) =>
    key.toLowerCase().replaceAll(RegExp(r'[-_\s]'), '');

/// v2rayNG style share link support.
///
/// Everything here is plain Dart on purpose: no Flutter, no core bindings, so
/// the conversions stay testable and cheap enough to run on the UI isolate.
class ShareLink {
  ShareLink._();

  /// Default group of a generated profile.
  static const String selectGroupName = 'PROXY';

  /// Default url-test group of a generated profile.
  static const String autoGroupName = 'AUTO';

  /// Delay test address used by generated url-test groups.
  static const String defaultTestUrl = 'https://www.gstatic.com/generate_204';

  /// Schemes that carry a single proxy server.
  static const Set<String> schemes = {
    'vmess',
    'vless',
    'trojan',
    'ss',
    'ssr',
    'shadowsocks',
    'shadowsocksr',
    'hysteria',
    'hysteria2',
    'hy2',
    'tuic',
    'wireguard',
    'wg',
    'anytls',
    'socks',
    'socks5',
  };

  static const Map<String, String> _schemeAliases = {
    'shadowsocks': 'ss',
    'shadowsocksr': 'ssr',
    'hy2': 'hysteria2',
    'wg': 'wireguard',
    'socks': 'socks5',
  };

  /// Longest first so that `ssr://` is never shadowed by `ss://`.
  static final RegExp _linkRegExp = RegExp(
    '(?:shadowsocksr|shadowsocks|hysteria2|hysteria|wireguard|socks5|socks|'
    'vmess|vless|trojan|anytls|tuic|hy2|ssr|ss|wg)://[^\\s<>"\']+',
    caseSensitive: false,
  );

  static final RegExp _anyUrlRegExp = RegExp(
    r'(?:https?|ftp|shadowsocksr|shadowsocks|hysteria2|hysteria|wireguard|'
    r'socks5|socks|vmess|vless|trojan|anytls|tuic|hy2|ssr|ss|wg)://'
    r'''[^\s<>"']+''',
    caseSensitive: false,
  );

  static final RegExp _subscriptionRegExp = RegExp(
    r"""(?:https?|ftp)://[^\s<>"']+""",
    caseSensitive: false,
  );

  /// `http://user:pass@host:port`, never a subscription address: those always
  /// carry a path, proxy share links do not.
  static final RegExp _proxyUrlRegExp = RegExp(
    r'^(?:https?)://[^/@\s]+@[^/\s]+:\d+(?:#[^/\s]*)?$',
    caseSensitive: false,
  );

  /// `clash://install-config?url=...`, the one-click import links Bettbox
  /// registers itself.
  static final RegExp _installConfigRegExp = RegExp(
    r'^(?:clash|clashmeta|mihomo|flclash|bettbox)://install-config[/?]',
    caseSensitive: false,
  );

  /// Keys that mark a Clash / Mihomo YAML config.
  static const List<String> _yamlMarkers = [
    'proxies:',
    'proxy-groups:',
    'proxy-providers:',
    'mixed-port:',
    'tun:',
    'rules:',
  ];

  // ---------------------------------------------------------------- detection

  /// Whether [text] is a single proxy share link (no surrounding noise).
  static bool isShareLink(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return false;
    final scheme = schemeOf(trimmed);
    if (scheme == null) return false;
    return !trimmed.substring(trimmed.indexOf('://') + 3).contains('\n');
  }

  /// Whether [text] holds anything importable besides a subscription URL.
  static bool isImportable(String text) =>
      detect(text) != ShareLinkContentKind.unknown;

  /// The canonical scheme of [text], or `null` when it is not a share link.
  static String? schemeOf(String text) {
    final trimmed = text.trim();
    final index = trimmed.indexOf('://');
    if (index <= 0) return null;
    final scheme = trimmed.substring(0, index).toLowerCase();
    if (!schemes.contains(scheme)) return null;
    return _schemeAliases[scheme] ?? scheme;
  }

  /// Classifies [text] without doing the full conversion.
  static ShareLinkContentKind detect(String text) {
    final trimmed = text.trim();
    if (trimmed.isEmpty) return ShareLinkContentKind.unknown;
    if (_containsShareLink(trimmed)) return ShareLinkContentKind.shareLink;
    if (_looksLikeProxyUrl(trimmed)) return ShareLinkContentKind.shareLink;
    if (_looksLikeYaml(trimmed)) return ShareLinkContentKind.yamlConfig;
    if (_installConfigUrl(trimmed) != null) {
      return ShareLinkContentKind.subscriptionUrl;
    }
    if (_firstPlainUrl(trimmed) != null) {
      return ShareLinkContentKind.subscriptionUrl;
    }
    final decoded = _decodeBase64Text(trimmed);
    if (decoded != null) {
      if (_containsShareLink(decoded) || _looksLikeProxyUrl(decoded.trim())) {
        return ShareLinkContentKind.shareLink;
      }
      if (_looksLikeYaml(decoded)) return ShareLinkContentKind.yamlConfig;
    }
    return ShareLinkContentKind.unknown;
  }

  /// Converts [text] into proxies / config content.
  static ShareLinkParseResult parse(String text) {
    var source = text.trim();
    if (source.isEmpty) return const ShareLinkParseResult();

    final directlyUsable = _containsShareLink(source) ||
        _looksLikeProxyUrl(source) ||
        _looksLikeYaml(source) ||
        _installConfigUrl(source) != null ||
        _firstPlainUrl(source) != null;
    if (!directlyUsable) {
      // Subscriptions copied as base64 blobs are common, unwrap them first.
      final decoded = _decodeBase64Text(source);
      if (decoded != null) source = decoded.trim();
    }

    if (!_containsShareLink(source) && _looksLikeProxyUrl(source)) {
      final proxy = _parseProxyUrl(source);
      if (proxy != null) {
        return ShareLinkParseResult(
          kind: ShareLinkContentKind.shareLink,
          proxies: [_uniqueNames([proxy])],
          linkCount: 1,
        );
      }
      return const ShareLinkParseResult();
    }

    if (!_containsShareLink(source)) {
      if (_looksLikeYaml(source)) {
        return ShareLinkParseResult(
          kind: ShareLinkContentKind.yamlConfig,
          yaml: source,
        );
      }
      final installUrl = _installConfigUrl(source);
      final url = installUrl ?? _firstPlainUrl(source);
      if (url != null) {
        return ShareLinkParseResult(
          kind: ShareLinkContentKind.subscriptionUrl,
          url: url,
        );
      }
      return const ShareLinkParseResult();
    }

    final proxies = <Map<String, Object?>>[];
    final failures = <ShareLinkFailure>[];
    for (final link in extractLinks(source)) {
      Map<String, Object?>? proxy;
      try {
        proxy = parseLink(link);
      } catch (error) {
        proxy = null;
        failures.add(
          ShareLinkFailure(link: link, reason: '$link: $error'),
        );
        continue;
      }
      if (proxy == null) {
        failures.add(
          ShareLinkFailure(
            link: link,
            reason: '$link: unsupported or malformed share link',
          ),
        );
        continue;
      }
      proxies.add(proxy);
    }

    if (proxies.isEmpty) {
      return ShareLinkParseResult(
        kind: ShareLinkContentKind.shareLink,
        failures: failures,
        linkCount: failures.length,
      );
    }

    return ShareLinkParseResult(
      kind: ShareLinkContentKind.shareLink,
      proxies: _uniqueNamesAll(proxies),
      failures: failures,
      linkCount: proxies.length + failures.length,
    );
  }

  /// Every share link inside [text], in order of appearance.
  static List<String> extractLinks(String text) {
    final links = <String>[];
    final matches = _anyUrlRegExp.allMatches(text);
    for (final match in matches) {
      final value = match.group(0);
      if (value == null) continue;
      final link = _trimLinkTail(value);
      final scheme = link.substring(0, link.indexOf('://')).toLowerCase();
      if (scheme == 'http' || scheme == 'https' || scheme == 'ftp') {
        // Plain addresses are subscriptions, only credential carrying ones
        // (`http://user:pass@host:port`) describe a proxy server.
        if (!_looksLikeProxyUrl(link)) continue;
      }
      links.add(link);
    }
    return links;
  }

  /// Converts one share link into a Mihomo proxy mapping.
  static Map<String, Object?>? parseLink(String link) {
    final scheme = schemeOf(link);
    if (scheme == null) {
      return _looksLikeProxyUrl(link.trim()) ? _parseProxyUrl(link.trim()) : null;
    }
    return switch (scheme) {
      'vmess' => _parseVmess(link),
      'vless' => _parseVless(link),
      'trojan' => _parseTrojan(link),
      'ss' => _parseShadowsocks(link),
      'ssr' => _parseShadowsocksR(link),
      'hysteria' => _parseHysteria(link),
      'hysteria2' => _parseHysteria2(link),
      'tuic' => _parseTuic(link),
      'wireguard' => _parseWireGuard(link),
      'anytls' => _parseAnyTLS(link),
      'socks5' => _parseSocks5(link),
      _ => null,
    };
  }

  // -------------------------------------------------------------- config text

  /// Builds a ready to save Mihomo config for [proxies].
  static String buildConfig(
    List<Map<String, Object?>> proxies, {
    String groupName = selectGroupName,
    String autoName = autoGroupName,
    String testUrl = defaultTestUrl,
  }) {
    final names = proxies.map((proxy) => '${proxy['name']}').toList();
    final config = <String, Object?>{
      'proxies': proxies,
      'proxy-groups': [
        <String, Object?>{
          'name': groupName,
          'type': 'select',
          'proxies': <Object?>[autoName, 'DIRECT', ...names],
        },
        <String, Object?>{
          'name': autoName,
          'type': 'url-test',
          'url': testUrl,
          'interval': 300,
          'tolerance': 50,
          'proxies': names,
        },
      ],
      'rules': <Object?>['MATCH,$groupName'],
    };
    final buffer = StringBuffer();
    buffer.writeln('# Generated by Bettbox from imported share links');
    _emitMap(buffer, config, 0);
    return buffer.toString();
  }

  /// First `name:` entry of a raw config, used to label pasted configs.
  static final RegExp _yamlNameRegExp = RegExp(
    r'^[ \t]*-?[ \t]*name:[ \t]*(.+?)[ \t]*$',
    multiLine: true,
  );

  /// A short human readable profile label for an import of [result].
  static String? suggestLabel(ShareLinkParseResult result) {
    final names = result.proxyNames;
    if (names.isNotEmpty) {
      return names.length == 1 ? names.first : '${names.first} +${names.length - 1}';
    }
    final yaml = result.yaml;
    if (yaml == null) return null;
    final name = _yamlNameRegExp.firstMatch(yaml)?.group(1)?.trim();
    if (name == null || name.isEmpty) return null;
    return name.replaceAll(RegExp(r'''^["']|["']$'''), '');
  }

  // ------------------------------------------------------------- protocols

  static Map<String, Object?>? _parseVmess(String link) {
    final payload = _stripScheme(link);
    final hashIndex = payload.indexOf('#');
    final encoded = hashIndex == -1 ? payload : payload.substring(0, hashIndex);
    var text = _decodeBase64Text(encoded)?.trim();
    if (text == null) return null;
    if (!text.startsWith('{')) {
      // Some panels hand out double encoded links.
      final nested = _decodeBase64Text(text)?.trim();
      if (nested != null && nested.startsWith('{')) text = nested;
    }
    if (!text.startsWith('{')) return null;

    Map<String, Object?> json;
    try {
      final decoded = jsonDecode(text);
      if (decoded is! Map) return null;
      json = decoded.cast<String, Object?>();
    } catch (_) {
      return null;
    }

    String field(String key) => '${json[key] ?? ''}'.trim();
    final server = field('add');
    final port = int.tryParse(field('port'));
    final uuid = field('id');
    if (server.isEmpty || uuid.isEmpty) return null;
    if (port == null || !_isValidPort(port)) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(field('ps'), fallback: '$server:$port'),
      'type': 'vmess',
      'server': server,
      'port': port,
      'uuid': uuid,
      'alterId': int.tryParse(field('aid')) ?? 0,
      'cipher': field('scy').isEmpty ? 'auto' : field('scy'),
      'udp': true,
    };

    final tls = field('tls').toLowerCase();
    final isReality = tls == 'reality';
    if (tls == 'tls' || isReality) proxy['tls'] = true;

    final serverName = _firstNotEmpty(field('sni'), field('servername'));
    if (serverName.isNotEmpty) proxy['servername'] = serverName;
    final fingerprint = field('fp');
    if (fingerprint.isNotEmpty) proxy['client-fingerprint'] = fingerprint;
    final alpn = _splitList(_firstNotEmpty(field('alpn'), field('alpns')));
    if (alpn.isNotEmpty) proxy['alpn'] = alpn;
    if (_boolValue(
          _firstNotEmpty(field('allowInsecure'), field('insecure')),
        ) ==
        true) {
      proxy['skip-cert-verify'] = true;
    }
    if (isReality) {
      final publicKey = field('pbk');
      if (publicKey.isNotEmpty) {
        final reality = <String, Object?>{'public-key': publicKey};
        final shortId = field('sid');
        if (shortId.isNotEmpty) reality['short-id'] = shortId;
        proxy['reality-opts'] = reality;
      }
      if (field('flow') == _xtlsFlow) proxy['flow'] = _xtlsFlow;
    }

    final query = <String, String>{};
    for (final entry in json.entries) {
      query[_normalizeKey(entry.key)] = '${entry.value ?? ''}';
    }
    _applyTransport(
      proxy,
      query,
      supported: const {'ws', 'h2', 'http', 'grpc', 'mkcp'},
      networkKeys: const ['net', 'network', 'type'],
      hostKeys: const ['host'],
      pathKeys: const ['path'],
      serviceNameKeys: const ['servicename', 'path'],
      earlyDataKeys: const ['ed', 'maxearlydata'],
      headerTypeKeys: const ['type', 'headertype'],
      seedKeys: const ['seed'],
    );
    return proxy;
  }

  static Map<String, Object?>? _parseVless(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    final port = parts.port;
    if (parts.userInfo.isEmpty || server.isEmpty) return null;
    if (port == null || !_isValidPort(port)) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:$port'),
      'type': 'vless',
      'server': server,
      'port': port,
      'uuid': parts.userInfo,
      'udp': true,
    };

    final security = (parts.param(['security']) ?? '').toLowerCase();
    final isReality = security == 'reality';
    if (security == 'tls' || security == 'xtls' || isReality) {
      proxy['tls'] = true;
    }
    final serverName = parts.param(['sni', 'servername', 'peer']);
    if (serverName != null) proxy['servername'] = serverName;
    final fingerprint = parts.param(['fp', 'fingerprint']);
    if (fingerprint != null) proxy['client-fingerprint'] = fingerprint;
    final alpn = _splitList(parts.param(['alpn']));
    if (alpn.isNotEmpty) proxy['alpn'] = alpn;
    if (parts.flag(['allowinsecure', 'insecure', 'skipcertverify']) == true) {
      proxy['skip-cert-verify'] = true;
    }
    final flow = parts.param(['flow']);
    if (flow == _xtlsFlow) proxy['flow'] = flow;
    final encryption = parts.param(['encryption']);
    if (encryption != null && encryption.toLowerCase() != 'none') {
      proxy['encryption'] = encryption;
    }
    if (isReality) {
      final publicKey = parts.param(['pbk', 'publickey']);
      if (publicKey != null) {
        final reality = <String, Object?>{'public-key': publicKey};
        final shortId = parts.param(['sid', 'shortid']);
        if (shortId != null) reality['short-id'] = shortId;
        proxy['reality-opts'] = reality;
      }
    }
    final packetEncoding = (parts.param(['packetencoding']) ?? '').toLowerCase();
    if (packetEncoding == 'packetaddr' || packetEncoding == 'packet') {
      proxy['packet-addr'] = true;
    }
    if (parts.flag(['xudp']) == true) proxy['xudp'] = true;
    if (parts.flag(['tfo', 'tcpfastopen']) == true) proxy['tfo'] = true;

    _applyTransport(proxy, parts.query, supported: _vlessTransports);
    return proxy;
  }

  static Map<String, Object?>? _parseTrojan(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    final port = parts.port;
    if (parts.userInfo.isEmpty || server.isEmpty) return null;
    if (port == null || !_isValidPort(port)) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:$port'),
      'type': 'trojan',
      'server': server,
      'port': port,
      'password': parts.userInfo,
      'udp': true,
    };

    final serverName = parts.param(['sni', 'peer', 'servername']);
    if (serverName != null) proxy['sni'] = serverName;
    final alpn = _splitList(parts.param(['alpn']));
    if (alpn.isNotEmpty) proxy['alpn'] = alpn;
    final fingerprint = parts.param(['fp', 'fingerprint']);
    if (fingerprint != null) proxy['client-fingerprint'] = fingerprint;
    if (parts.flag(['allowinsecure', 'insecure', 'skipcertverify']) == true) {
      proxy['skip-cert-verify'] = true;
    }
    final flow = parts.param(['flow']);
    if (flow == _xtlsFlow) proxy['flow'] = flow;
    final publicKey = parts.param(['pbk', 'publickey']);
    if (publicKey != null) {
      final reality = <String, Object?>{'public-key': publicKey};
      final shortId = parts.param(['sid', 'shortid']);
      if (shortId != null) reality['short-id'] = shortId;
      proxy['reality-opts'] = reality;
    }
    // Trojan in Mihomo only speaks ws / grpc on top of TLS.
    _applyTransport(proxy, parts.query, supported: const {'ws', 'grpc'});
    return proxy;
  }

  static Map<String, Object?>? _parseShadowsocks(String link) {
    var parts = _splitLink(link);
    if (parts == null) return null;

    var auth = parts.userInfo;
    var server = parts.host;
    var port = parts.port;
    var remark = parts.fragment;

    if (auth.isEmpty) {
      // Legacy form: the whole `method:password@host:port` part is base64.
      final decoded = _decodeBase64Text(parts.host);
      if (decoded != null && decoded.contains('@')) {
        final legacy = _splitLink('${parts.scheme}://$decoded');
        if (legacy == null) return null;
        if (legacy.fragment.isNotEmpty) remark = legacy.fragment;
        parts = legacy;
        auth = legacy.userInfo;
        server = legacy.host;
        port = legacy.port;
      }
    }

    var cipher = '';
    var password = auth;
    if (auth.isNotEmpty) {
      final decoded = _decodeBase64Text(auth);
      if (decoded != null && decoded.contains(':')) {
        final index = decoded.indexOf(':');
        cipher = decoded.substring(0, index);
        password = decoded.substring(index + 1);
      } else if (auth.contains(':')) {
        final index = auth.indexOf(':');
        cipher = auth.substring(0, index);
        password = auth.substring(index + 1);
      } else {
        return null;
      }
    } else {
      return null;
    }

    if (server.isEmpty || cipher.isEmpty) return null;
    if (port == null || !_isValidPort(port)) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(remark, fallback: '$server:$port'),
      'type': 'ss',
      'server': server,
      'port': port,
      'cipher': cipher,
      'password': password,
      'udp': true,
    };

    final plugin = parts.param(['plugin', 'obfs']);
    if (plugin != null) {
      final pluginOpts = _parseSsPlugin(plugin, parts);
      if (pluginOpts != null) {
        proxy['plugin'] = pluginOpts.$1;
        if (pluginOpts.$2.isNotEmpty) proxy['plugin-opts'] = pluginOpts.$2;
      }
    }
    if (parts.flag(['uot', 'udpovertcp']) == true) proxy['udp-over-tcp'] = true;
    return proxy;
  }

  static (String, Map<String, Object?>)? _parseSsPlugin(
    String plugin,
    _LinkParts parts,
  ) {
    final decoded = _decodePercent(plugin);
    final segments = decoded
        .split(RegExp(r'[;,\s]+'))
        .where((item) => item.isNotEmpty)
        .toList();
    if (segments.isEmpty) return null;

    final options = <String, Object?>{};
    for (final segment in segments.skip(1)) {
      final index = segment.indexOf('=');
      if (index < 0) {
        // Valueless segments (`;tls`, `;mux`) are flags.
        final flag = _normalizeKey(segment);
        if (flag.isNotEmpty) options[flag] = true;
        continue;
      }
      if (index == 0) continue;
      options[_normalizeKey(segment.substring(0, index))] =
          _decodePercent(segment.substring(index + 1));
    }
    // Panels sometimes ship the plugin settings as regular query parameters.
    for (final key in [
      'mode',
      'host',
      'obfs',
      'obfshost',
      'path',
      'tls',
      'mux',
      'skipcertverify',
    ]) {
      if (options.containsKey(key)) continue;
      final value = parts.param([key]);
      if (value != null) options[key] = value;
    }

    // simple-obfs spells its keys `obfs` / `obfs-host`.
    String? option(List<String> keys) {
      for (final key in keys) {
        final value = options[key];
        if (value != null && '$value'.isNotEmpty) return '$value';
      }
      return null;
    }

    final name = segments.first.toLowerCase();
    final pluginOpts = <String, Object?>{};
    final host = option(['host', 'obfshost']);
    if (name.contains('v2ray')) {
      pluginOpts['mode'] = option(['mode']) ?? 'websocket';
      if (host != null) pluginOpts['host'] = host;
      final path = option(['path']);
      if (path != null) {
        pluginOpts['path'] = path.startsWith('/') ? path : '/$path';
      }
      if (_boolValue(option(['tls'])) == true) pluginOpts['tls'] = true;
      if (_boolValue(option(['mux'])) == true) pluginOpts['mux'] = true;
      if (_boolValue(option(['skipcertverify', 'insecure'])) == true) {
        pluginOpts['skip-cert-verify'] = true;
      }
      return ('v2ray-plugin', pluginOpts);
    }
    if (name.contains('obfs') || name.contains('simple')) {
      pluginOpts['mode'] = option(['mode', 'obfs']) == 'tls' ? 'tls' : 'http';
      if (host != null) pluginOpts['host'] = host;
      return ('obfs', pluginOpts);
    }
    return null;
  }

  static Map<String, Object?>? _parseShadowsocksR(String link) {
    final payload = _stripScheme(link);
    final decoded = _decodeBase64Text(payload);
    if (decoded == null) return null;

    // `host:port:protocol:method:obfs:base64(password)/?params`, the password
    // may itself contain `/` so prefer the `/?` separator when it is there.
    String main;
    String queryText;
    final paramsIndex = decoded.indexOf('/?');
    if (paramsIndex != -1) {
      main = decoded.substring(0, paramsIndex);
      queryText = decoded.substring(paramsIndex + 2);
    } else {
      final slashIndex = decoded.indexOf('/');
      main = slashIndex == -1 ? decoded : decoded.substring(0, slashIndex);
      queryText = slashIndex == -1 ? '' : decoded.substring(slashIndex + 1);
    }

    final segments = main.split(':');
    if (segments.length < 6) return null;
    final server = segments[0];
    final port = int.tryParse(segments[1]);
    final protocol = segments[2];
    final cipher = segments[3];
    final obfs = segments[4];
    final encodedPassword = segments.sublist(5).join(':');
    final password = _decodeBase64Text(encodedPassword) ?? encodedPassword;
    if (server.isEmpty || password.isEmpty) return null;
    if (port == null || !_isValidPort(port)) return null;

    final query = _parseQuery(queryText.replaceAll('?', ''));
    String? value(String key) {
      final raw = query[_normalizeKey(key)];
      if (raw == null || raw.isEmpty) return null;
      return _decodeBase64Text(raw) ?? raw;
    }

    final proxy = <String, Object?>{
      'name': _cleanName(value('remarks') ?? '', fallback: '$server:$port'),
      'type': 'ssr',
      'server': server,
      'port': port,
      'cipher': cipher,
      'password': password,
      'obfs': obfs,
      'protocol': protocol,
      'udp': true,
    };
    final obfsParam = value('obfsparam');
    if (obfsParam != null) proxy['obfs-param'] = obfsParam;
    final protocolParam = value('protoparam') ?? value('protocolparam');
    if (protocolParam != null) proxy['protocol-param'] = protocolParam;
    return proxy;
  }

  static Map<String, Object?>? _parseHysteria(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    final port = parts.port;
    if (server.isEmpty) return null;

    final auth = parts.param(['authstr', 'authstring', 'auth']);
    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:${port ?? 443}'),
      'type': 'hysteria',
      'server': server,
    };
    if (port != null && _isValidPort(port)) proxy['port'] = port;
    if (proxy['port'] == null && parts.portRange == null) return null;
    proxy['up'] = parts.param(['upmbps', 'up']) ?? '100';
    proxy['down'] = parts.param(['downmbps', 'down']) ?? '100';

    if (auth != null) {
      // v1 share links carry the auth string base64 encoded.
      final decoded = _decodeBase64Text(auth);
      proxy['auth-str'] = decoded ?? auth;
    } else if (parts.userInfo.isNotEmpty) {
      proxy['auth-str'] = parts.userInfo;
    }
    final protocol = parts.param(['protocol']);
    if (protocol != null) proxy['protocol'] = protocol;
    final sni = parts.param(['sni', 'peer', 'servername']);
    if (sni != null) proxy['sni'] = sni;
    final alpn = _splitList(parts.param(['alpn']));
    if (alpn.isNotEmpty) proxy['alpn'] = alpn;
    final obfs = parts.param(['obfsparam', 'obfs']);
    if (obfs != null) proxy['obfs'] = _decodeBase64Text(obfs) ?? obfs;
    if (parts.flag(['insecure', 'allowinsecure']) == true) {
      proxy['skip-cert-verify'] = true;
    }
    if (parts.flag(['fastopen']) == true) proxy['fast-open'] = true;
    final ports = parts.portRange ?? parts.param(['mport', 'ports']);
    if (ports != null) proxy['ports'] = ports;
    return proxy;
  }

  static Map<String, Object?>? _parseHysteria2(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    if (server.isEmpty) return null;
    final password = parts.param(['password']) ?? parts.userInfo;
    if (password.isEmpty) return null;

    final port = parts.port;
    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:${port ?? 443}'),
      'type': 'hysteria2',
      'server': server,
      'password': password,
    };
    if (port != null && _isValidPort(port)) proxy['port'] = port;
    final sni = parts.param(['sni', 'servername', 'peer']);
    if (sni != null) proxy['sni'] = sni;
    final alpn = _splitList(parts.param(['alpn']));
    if (alpn.isNotEmpty) proxy['alpn'] = alpn;
    final obfs = parts.param(['obfs']);
    if (obfs != null && obfs.toLowerCase() != 'none') proxy['obfs'] = obfs;
    final obfsPassword = parts.param(['obfspassword', 'obfspwd']);
    if (obfsPassword != null) proxy['obfs-password'] = obfsPassword;
    if (parts.flag(['insecure', 'allowinsecure']) == true) {
      proxy['skip-cert-verify'] = true;
    }
    final ports = parts.portRange ?? parts.param(['mport', 'ports']);
    if (ports != null) proxy['ports'] = ports;
    if (proxy['port'] == null && proxy['ports'] == null) return null;
    final up = parts.param(['up', 'upmbps']);
    if (up != null) proxy['up'] = up;
    final down = parts.param(['down', 'downmbps']);
    if (down != null) proxy['down'] = down;
    return proxy;
  }

  static Map<String, Object?>? _parseTuic(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    final port = parts.port;
    if (server.isEmpty || port == null || !_isValidPort(port)) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:$port'),
      'type': 'tuic',
      'server': server,
      'port': port,
    };

    var auth = parts.userInfo;
    if (auth.contains(':')) {
      final index = auth.indexOf(':');
      final uuid = auth.substring(0, index);
      final password = auth.substring(index + 1);
      if (uuid.isNotEmpty) proxy['uuid'] = uuid;
      if (password.isNotEmpty) proxy['password'] = password;
    } else if (auth.isNotEmpty) {
      // tuic v4 style links only carry a token.
      proxy['token'] = auth;
    }
    final token = parts.param(['token']);
    if (token != null && proxy['token'] == null) proxy['token'] = token;

    final sni = parts.param(['sni', 'servername', 'peer']);
    if (sni != null) proxy['sni'] = sni;
    final alpn = _splitList(parts.param(['alpn']));
    if (alpn.isNotEmpty) proxy['alpn'] = alpn;
    final congestion = parts.param(['congestioncontrol', 'congestion']);
    if (congestion != null) proxy['congestion-controller'] = congestion;
    final udpRelayMode = parts.param(['udprelaymode', 'udprelay']);
    if (udpRelayMode != null) proxy['udp-relay-mode'] = udpRelayMode;
    if (parts.flag(['disablesni']) == true) proxy['disable-sni'] = true;
    if (parts.flag(['allowinsecure', 'insecure']) == true) {
      proxy['skip-cert-verify'] = true;
    }
    final heartbeat = parts.param(['heartbeat', 'heartbeatinterval']);
    final heartbeatValue = int.tryParse(heartbeat ?? '');
    if (heartbeatValue != null && heartbeatValue > 0) {
      proxy['heartbeat-interval'] = heartbeatValue;
    }
    if (parts.flag(['reducertt']) == true) proxy['reduce-rtt'] = true;
    return proxy;
  }

  static Map<String, Object?>? _parseWireGuard(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    final port = parts.port;
    if (server.isEmpty || port == null || !_isValidPort(port)) return null;

    final privateKey = _toStdBase64(parts.userInfo);
    final publicKey = _toStdBase64(parts.param(['publickey', 'pubkey']) ?? '');
    if (privateKey.isEmpty || publicKey.isEmpty) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:$port'),
      'type': 'wireguard',
      'server': server,
      'port': port,
      'private-key': privateKey,
      'public-key': publicKey,
      'udp': true,
    };

    final preSharedKey = _toStdBase64(
      parts.param(['presharedkey', 'psk']) ?? '',
    );
    if (preSharedKey.isNotEmpty) proxy['pre-shared-key'] = preSharedKey;

    final allowedIps = _splitList(
      parts.param(['allowedips', 'allowedip', 'aip']) ?? '0.0.0.0/0',
    );
    if (allowedIps.isNotEmpty) proxy['allowed-ips'] = allowedIps;

    final mtu = int.tryParse(parts.param(['mtu']) ?? '');
    if (mtu != null && mtu > 0) proxy['mtu'] = mtu;
    final workers = int.tryParse(parts.param(['workers']) ?? '');
    if (workers != null && workers > 0) proxy['workers'] = workers;
    final keepAlive = int.tryParse(
      parts.param(['persistentkeepalive', 'keepalive']) ?? '',
    );
    if (keepAlive != null && keepAlive > 0) {
      proxy['persistent-keepalive'] = keepAlive;
    }

    final reserved = _parseReserved(parts.param(['reserved']));
    if (reserved != null) proxy['reserved'] = reserved;

    // Mihomo needs a local interface address, share links rarely carry one.
    final local = parts.param(['localip', 'ip', 'localaddress', 'address']);
    final addresses = _splitList(local ?? '');
    final v4 = addresses.where((item) => !item.contains(':')).toList();
    final v6 = addresses.where((item) => item.contains(':')).toList();
    proxy['ip'] = v4.isNotEmpty ? v4.first : _wireGuardFallbackIp(privateKey);
    if (v6.isNotEmpty) proxy['ipv6'] = v6.first;

    final dns = _splitList(parts.param(['dns']));
    if (dns.isNotEmpty) {
      proxy['dns'] = dns;
      proxy['remote-dns-resolve'] = true;
    }
    return proxy;
  }

  static Map<String, Object?>? _parseAnyTLS(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    final port = parts.port;
    final password = parts.param(['password']) ?? parts.userInfo;
    if (server.isEmpty || password.isEmpty) return null;
    if (port == null || !_isValidPort(port)) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:$port'),
      'type': 'anytls',
      'server': server,
      'port': port,
      'password': password,
      'udp': true,
    };
    final sni = parts.param(['sni', 'servername', 'peer']);
    if (sni != null) proxy['sni'] = sni;
    final alpn = _splitList(parts.param(['alpn']));
    if (alpn.isNotEmpty) proxy['alpn'] = alpn;
    final fingerprint = parts.param(['fp', 'fingerprint']);
    if (fingerprint != null) proxy['client-fingerprint'] = fingerprint;
    if (parts.flag(['insecure', 'allowinsecure']) == true) {
      proxy['skip-cert-verify'] = true;
    }
    final clientMetadata = parts.param(['clientmetadata', 'padding']);
    if (clientMetadata != null) proxy['client-metadata'] = clientMetadata;
    return proxy;
  }

  static Map<String, Object?>? _parseSocks5(String link) {
    final parts = _splitLink(link);
    if (parts == null) return null;
    final server = parts.host;
    final port = parts.port;
    if (server.isEmpty || port == null || !_isValidPort(port)) return null;

    final proxy = <String, Object?>{
      'name': _cleanName(parts.fragment, fallback: '$server:$port'),
      'type': 'socks5',
      'server': server,
      'port': port,
      'udp': true,
    };
    final auth = parts.userInfo;
    if (auth.contains(':')) {
      final index = auth.indexOf(':');
      proxy['username'] = auth.substring(0, index);
      proxy['password'] = auth.substring(index + 1);
    } else if (auth.isNotEmpty) {
      proxy['username'] = auth;
    }
    if (parts.flag(['tls', 'over_tls', 'overtls']) == true) proxy['tls'] = true;
    if (parts.flag(['allowinsecure', 'insecure']) == true) {
      proxy['skip-cert-verify'] = true;
    }
    return proxy;
  }

  static Map<String, Object?>? _parseProxyUrl(String link) {
    final trimmed = link.trim();
    if (!_looksLikeProxyUrl(trimmed)) return null;
    final index = trimmed.indexOf('://');
    final scheme = trimmed.substring(0, index).toLowerCase();
    final rest = trimmed.substring(index + 3);
    final authority = rest.split(RegExp(r'[/?#]')).first;
    final atIndex = authority.lastIndexOf('@');
    if (atIndex == -1) return null;

    final auth = _decodePercent(authority.substring(0, atIndex));
    final hostPort = authority.substring(atIndex + 1);
    final colonIndex = hostPort.lastIndexOf(':');
    if (colonIndex == -1) return null;
    final server = hostPort.substring(0, colonIndex);
    final port = int.tryParse(hostPort.substring(colonIndex + 1));
    if (server.isEmpty || port == null || !_isValidPort(port)) return null;

    final nameSource = trimmed.contains('#')
        ? _decodePercent(trimmed.substring(trimmed.indexOf('#') + 1))
        : '';
    final proxy = <String, Object?>{
      'name': _cleanName(nameSource, fallback: '$server:$port'),
      'type': 'http',
      'server': server,
      'port': port,
    };
    if (scheme == 'https') proxy['tls'] = true;
    if (auth.contains(':')) {
      final authIndex = auth.indexOf(':');
      proxy['username'] = auth.substring(0, authIndex);
      proxy['password'] = auth.substring(authIndex + 1);
    } else {
      proxy['username'] = auth;
    }
    return proxy;
  }

  // -------------------------------------------------------------- transports

  static const String _xtlsFlow = 'xtls-rprx-vision';

  static const Set<String> _vlessTransports = {
    'ws',
    'h2',
    'http',
    'grpc',
    'xhttp',
  };

  static void _applyTransport(
    Map<String, Object?> proxy,
    Map<String, String> query, {
    required Set<String> supported,
    List<String> networkKeys = const ['type', 'network', 'net'],
    List<String> hostKeys = const ['host'],
    List<String> pathKeys = const ['path'],
    List<String> serviceNameKeys = const [
      'servicename',
      'service-name',
      'authority',
      'grpcservicename',
    ],
    List<String> earlyDataKeys = const ['ed', 'maxearlydata', 'earlydata'],
    List<String> headerTypeKeys = const ['headertype', 'type'],
    List<String> seedKeys = const ['seed'],
  }) {
    String? value(List<String> keys) {
      for (final key in keys) {
        final raw = query[_normalizeKey(key)];
        if (raw != null && raw.isNotEmpty) return raw;
      }
      return null;
    }

    final network = _normalizeNetwork(value(networkKeys) ?? '');
    if (network == null) return;
    // httpUpgrade is carried by the ws transport in Mihomo.
    final isHttpUpgrade = network == 'httpupgrade';
    if (!supported.contains(network) &&
        !(isHttpUpgrade && supported.contains('ws'))) {
      return;
    }

    final host = value(hostKeys) ?? '';
    // h2 / http accept a host list, share links join them with commas.
    final hosts = _splitList(host);
    final rawPath = value(pathKeys) ?? '';
    final path = rawPath.isEmpty ? '' : (rawPath.startsWith('/') ? rawPath : '/$rawPath');
    final serviceName = value(serviceNameKeys) ?? '';
    final earlyData = int.tryParse(value(earlyDataKeys) ?? '') ?? 0;
    final headers = <String, Object?>{};
    if (hosts.isNotEmpty) headers['Host'] = hosts.first;

    switch (network) {
      case 'ws':
        proxy['network'] = 'ws';
        final wsOpts = <String, Object?>{};
        if (path.isNotEmpty) wsOpts['path'] = path;
        if (headers.isNotEmpty) wsOpts['headers'] = headers;
        if (earlyData > 0) {
          wsOpts['max-early-data'] = earlyData;
          wsOpts['early-data-header-name'] = 'Sec-WebSocket-Protocol';
        }
        if (wsOpts.isNotEmpty) proxy['ws-opts'] = wsOpts;
      case 'httpupgrade':
        proxy['network'] = 'ws';
        proxy['ws-opts'] = <String, Object?>{
          if (path.isNotEmpty) 'path': path,
          if (headers.isNotEmpty) 'headers': headers,
          'v2ray-http-upgrade': true,
          if (_boolValue(query[_normalizeKey('fastopen')]) == true)
            'v2ray-http-upgrade-fast-open': true,
        };
      case 'h2':
        proxy['network'] = 'h2';
        proxy['h2-opts'] = <String, Object?>{
          if (hosts.isNotEmpty) 'host': hosts,
          'path': path.isEmpty ? '/' : path,
        };
      case 'http':
        proxy['network'] = 'http';
        proxy['http-opts'] = <String, Object?>{
          'method': value(['method']) ?? 'GET',
          'path': <Object?>[path.isEmpty ? '/' : path],
          if (hosts.isNotEmpty) 'headers': <String, Object?>{'Host': hosts},
        };
      case 'grpc':
        proxy['network'] = 'grpc';
        final grpcOpts = <String, Object?>{
          'grpc-service-name': serviceName.isEmpty ? path : serviceName,
        };
        final userAgent = value(['useragent', 'grpcuseragent', 'ua']);
        if (userAgent != null) grpcOpts['grpc-user-agent'] = userAgent;
        proxy['grpc-opts'] = grpcOpts;
      case 'xhttp':
        proxy['network'] = 'xhttp';
        final xhttpOpts = <String, Object?>{
          if (path.isNotEmpty) 'path': path,
          if (host.isNotEmpty) 'host': host,
        };
        final mode = value(['mode', 'xhttpmode', 'xhttpMode']);
        if (mode != null) xhttpOpts['mode'] = mode;
        final noGrpcHeader = query[_normalizeKey('nogrpcheader')];
        if (_boolValue(noGrpcHeader) == true) xhttpOpts['no-grpc-header'] = true;
        if (xhttpOpts.isNotEmpty) proxy['xhttp-opts'] = xhttpOpts;
      case 'mkcp':
        proxy['network'] = 'mkcp';
        final header = value(headerTypeKeys) ?? '';
        final seed = value(seedKeys) ?? '';
        final mkcpOpts = <String, Object?>{};
        if (header.isNotEmpty && header != 'none') mkcpOpts['header'] = header;
        if (seed.isNotEmpty) mkcpOpts['seed'] = seed;
        if (mkcpOpts.isNotEmpty) proxy['mkcp-opts'] = mkcpOpts;
    }
  }

  /// Maps the transport names used by share links onto Mihomo values.
  static String? _normalizeNetwork(String value) {
    return switch (value.trim().toLowerCase()) {
      'ws' || 'websocket' => 'ws',
      'httpupgrade' => 'httpupgrade',
      'h2' || 'http2' => 'h2',
      'http' => 'http',
      'grpc' || 'gun' => 'grpc',
      'xhttp' || 'splithttp' => 'xhttp',
      'kcp' || 'mkcp' => 'mkcp',
      'tcp' || 'raw' || 'none' || '' => null,
      _ => null,
    };
  }

  // ------------------------------------------------------------ link parsing

  static String _stripScheme(String link) {
    final index = link.indexOf('://');
    return index == -1 ? link : link.substring(index + 3);
  }

  static _LinkParts? _splitLink(String link) {
    final trimmed = link.trim();
    final schemeIndex = trimmed.indexOf('://');
    if (schemeIndex <= 0) return null;
    final scheme = trimmed.substring(0, schemeIndex).toLowerCase();
    var rest = trimmed.substring(schemeIndex + 3);

    var fragment = '';
    final hashIndex = rest.indexOf('#');
    if (hashIndex != -1) {
      fragment = rest.substring(hashIndex + 1);
      rest = rest.substring(0, hashIndex);
    }

    var queryText = '';
    final queryIndex = rest.indexOf('?');
    if (queryIndex != -1) {
      queryText = rest.substring(queryIndex + 1);
      rest = rest.substring(0, queryIndex);
    }

    var userInfo = '';
    final atIndex = rest.lastIndexOf('@');
    if (atIndex != -1) {
      userInfo = rest.substring(0, atIndex);
      rest = rest.substring(atIndex + 1);
    }

    // Share links never carry a path, but panels like to emit `host:port/?x`.
    // Only strip it when the authority really looks like one, base64 payloads
    // (legacy `ss://`) may contain `/` as well.
    final slashIndex = rest.indexOf('/');
    if (slashIndex != -1) {
      final authority = rest.substring(0, slashIndex);
      if (atIndex != -1 || _looksLikeHostPort(authority)) {
        rest = authority;
      }
    }

    var host = rest;
    int? port;
    String? portRange;
    if (host.startsWith('[')) {
      final closeIndex = host.indexOf(']');
      if (closeIndex != -1) {
        final tail = host.substring(closeIndex + 1);
        host = host.substring(1, closeIndex);
        if (tail.startsWith(':')) port = int.tryParse(tail.substring(1));
      }
    } else {
      final colonIndex = host.lastIndexOf(':');
      if (colonIndex != -1) {
        final tail = host.substring(colonIndex + 1);
        final candidate = int.tryParse(tail);
        if (candidate != null) {
          port = candidate;
          host = host.substring(0, colonIndex);
        } else if (_portRangeRegExp.hasMatch(tail)) {
          portRange = tail;
          host = host.substring(0, colonIndex);
        }
      }
    }

    return _LinkParts(
      scheme: scheme,
      userInfo: _decodePercent(userInfo),
      host: _decodePercent(host).trim(),
      port: port,
      query: _parseQuery(queryText),
      fragment: _decodePercent(fragment).trim(),
      portRange: portRange,
    );
  }

  static final RegExp _portRangeRegExp = RegExp(r'^\d+[-,/]\d+(?:[-,/]\d+)*$');

  /// `host:port` (or `host:port-port`), used to tell an authority from a
  /// base64 payload that happens to contain `/`.
  static bool _looksLikeHostPort(String value) {
    final colonIndex = value.lastIndexOf(':');
    if (colonIndex == -1 || colonIndex == value.length - 1) return false;
    final tail = value.substring(colonIndex + 1);
    return int.tryParse(tail) != null || _portRangeRegExp.hasMatch(tail);
  }

  static Map<String, String> _parseQuery(String queryText) {
    final query = <String, String>{};
    if (queryText.isEmpty) return query;
    for (final pair in queryText.split(RegExp(r'[&;]'))) {
      if (pair.isEmpty) continue;
      final index = pair.indexOf('=');
      if (index == -1) {
        query[_normalizeKey(_decodePercent(pair))] = '';
        continue;
      }
      final key = _normalizeKey(pair.substring(0, index));
      if (key.isEmpty) continue;
      query[key] = _decodePercent(pair.substring(index + 1));
    }
    return query;
  }

  // ------------------------------------------------------------------ helpers

  static bool _containsShareLink(String text) => _linkRegExp.hasMatch(text);

  /// First plain `http(s)` / `ftp` address in [text], if any.
  /// The subscription address carried by an `install-config` one-click link.
  static String? _installConfigUrl(String text) {
    final trimmed = text.trim();
    if (!_installConfigRegExp.hasMatch(trimmed)) return null;
    final index = trimmed.indexOf('?');
    if (index < 0) return null;
    for (final pair in trimmed.substring(index + 1).split('&')) {
      final eq = pair.indexOf('=');
      if (eq <= 0) continue;
      if (pair.substring(0, eq).toLowerCase() != 'url') continue;
      final value = _decodePercent(pair.substring(eq + 1));
      if (value.isNotEmpty) return value;
    }
    return null;
  }

  static String? _firstPlainUrl(String text) {
    final match = _subscriptionRegExp.firstMatch(text);
    final value = match?.group(0);
    if (value == null) return null;
    final url = _trimLinkTail(value);
    // Credential carrying addresses without a path are proxy servers.
    if (_looksLikeProxyUrl(url)) return null;
    return url;
  }

  static bool _looksLikeProxyUrl(String text) =>
      _proxyUrlRegExp.hasMatch(text.trim());

  static bool _looksLikeYaml(String text) {
    final lowered = text.toLowerCase();
    if (!lowered.contains(':')) return false;
    var hits = 0;
    for (final marker in _yamlMarkers) {
      if (lowered.contains(marker)) hits++;
    }
    return hits >= 2 || lowered.contains('proxies:');
  }

  static bool _isValidPort(int port) => port > 0 && port <= 65535;

  static String _trimLinkTail(String link) {
    var value = link;
    const tails = [',', ';', ')', ']', '}', '"', "'", '>', '。', '，'];
    var changed = true;
    while (changed && value.isNotEmpty) {
      changed = false;
      for (final tail in tails) {
        if (value.endsWith(tail)) {
          value = value.substring(0, value.length - tail.length);
          changed = true;
        }
      }
    }
    return value;
  }

  /// Decodes `%XX` sequences without touching `+`, share links use `+` inside
  /// passwords and base64 payloads.
  static String _decodePercent(String value) {
    if (value.isEmpty || !value.contains('%')) return value;
    final buffer = StringBuffer();
    final bytes = <int>[];
    void flush() {
      if (bytes.isEmpty) return;
      buffer.write(utf8.decode(bytes, allowMalformed: true));
      bytes.clear();
    }

    for (var i = 0; i < value.length; i++) {
      final char = value[i];
      if (char == '%' && i + 2 < value.length) {
        final code = int.tryParse(value.substring(i + 1, i + 3), radix: 16);
        if (code != null) {
          bytes.add(code);
          i += 2;
          continue;
        }
      }
      flush();
      buffer.write(char);
    }
    flush();
    return buffer.toString();
  }

  static Uint8List? _decodeBase64Bytes(String input) {
    final cleaned = input.replaceAll(RegExp(r'\s'), '');
    if (cleaned.length < 4) return null;
    final variants = <String>{
      cleaned,
      cleaned.replaceAll('-', '+').replaceAll('_', '/'),
      cleaned.replaceAll('+', '-').replaceAll('/', '_'),
    };
    for (final variant in variants) {
      var candidate = variant;
      final remainder = candidate.length % 4;
      if (remainder == 1) continue;
      if (remainder != 0) candidate = candidate.padRight(
        candidate.length + (4 - remainder),
        '=',
      );
      for (final decoder in [base64, base64Url]) {
        try {
          return decoder.decode(candidate);
        } catch (_) {
          // Try the next variant.
        }
      }
    }
    return null;
  }

  static String? _decodeBase64Text(String input) {
    final bytes = _decodeBase64Bytes(input);
    if (bytes == null) return null;
    try {
      return utf8.decode(bytes);
    } catch (_) {
      final text = utf8.decode(bytes, allowMalformed: true);
      // Binary garbage decodes "successfully" with replacement characters.
      if (text.contains('\uFFFD')) return null;
      return text;
    }
  }

  /// Re-encodes a base64url key as standard base64, as Mihomo expects.
  static String _toStdBase64(String value) {
    final trimmed = value.trim();
    if (trimmed.isEmpty) return '';
    final bytes = _decodeBase64Bytes(trimmed);
    if (bytes == null) return trimmed;
    return base64.encode(bytes);
  }

  static List<int>? _parseReserved(String? value) {
    if (value == null || value.isEmpty) return null;
    final numbers = value
        .split(RegExp(r'[,\s]+'))
        .map((item) => int.tryParse(item.trim()))
        .toList();
    if (numbers.length == 3 && numbers.every((item) => item != null)) {
      return numbers.cast<int>();
    }
    final bytes = _decodeBase64Bytes(value);
    if (bytes != null && bytes.length == 3) return bytes.toList();
    return null;
  }

  /// Stable private address for WireGuard links without a local address.
  static String _wireGuardFallbackIp(String privateKey) {
    final bytes = _decodeBase64Bytes(privateKey);
    var seed = 0;
    if (bytes != null && bytes.isNotEmpty) {
      for (final byte in bytes) {
        seed = (seed * 31 + byte) & 0x7fffffff;
      }
    } else {
      // Deterministic on purpose: `hashCode` is randomized per run.
      for (final unit in privateKey.codeUnits) {
        seed = (seed * 31 + unit) & 0x7fffffff;
      }
    }
    final third = (seed >> 8) % 32;
    final fourth = 2 + (seed % 253);
    return '172.16.$third.$fourth';
  }

  static bool? _boolValue(String? value) {
    if (value == null) return null;
    return switch (value.trim().toLowerCase()) {
      '1' || 'true' || 'yes' || 'on' => true,
      '0' || 'false' || 'no' || 'off' => false,
      _ => null,
    };
  }

  static List<String> _splitList(String? value) {
    if (value == null || value.trim().isEmpty) return const [];
    return value
        .split(RegExp(r'[,\s]+'))
        .map((item) => item.trim())
        .where((item) => item.isNotEmpty)
        .toList();
  }

  static String _firstNotEmpty(String first, String second) =>
      first.isNotEmpty ? first : second;

  static String _cleanName(String value, {required String fallback}) {
    // ignore: control_characters_in_string
    final cleaned = value
        .replaceAll(RegExp(r'[\u0000-\u001f\u007f]'), '')
        .trim();
    if (cleaned.isEmpty) return fallback;
    return cleaned.length > 96 ? cleaned.substring(0, 96) : cleaned;
  }

  static Map<String, Object?> _uniqueNames(Map<String, Object?> proxy) =>
      _uniqueNamesAll([proxy]).first;

  static List<Map<String, Object?>> _uniqueNamesAll(
    List<Map<String, Object?>> proxies,
  ) {
    final used = <String>{};
    final result = <Map<String, Object?>>[];
    for (final proxy in proxies) {
      var name = '${proxy['name']}';
      if (used.contains(name)) {
        var index = 2;
        while (used.contains('$name $index')) {
          index++;
        }
        name = '$name $index';
      }
      used.add(name);
      result.add(name == proxy['name'] ? proxy : {...proxy, 'name': name});
    }
    return result;
  }

  // ------------------------------------------------------------- yaml output

  static String _indent(int level) => '  ' * level;

  /// Keys used here are known safe literals, values are always quoted.
  static String _yamlScalar(Object? value) {
    return switch (value) {
      null => '""',
      bool value => value ? 'true' : 'false',
      num value => '$value',
      List value => value.isEmpty
          ? '[]'
          : '[${value.map(_yamlScalar).join(', ')}]',
      Map value => value.isEmpty
          ? '{}'
          : '{${value.entries.map((entry) => '${entry.key}: ${_yamlScalar(entry.value)}').join(', ')}}',
      _ => '"${_escapeYaml('$value')}"',
    };
  }

  static String _escapeYaml(String value) {
    final buffer = StringBuffer();
    for (final codeUnit in value.runes) {
      switch (codeUnit) {
        case 0x22: // "
          buffer.write(r'\"');
        case 0x5C: // \
          buffer.write(r'\\');
        case 0x0A: // \n
          buffer.write(r'\n');
        case 0x0D: // \r
          buffer.write(r'\r');
        case 0x09: // \t
          buffer.write(r'\t');
        default:
          if (codeUnit < 0x20 || codeUnit == 0x7F) continue;
          buffer.writeCharCode(codeUnit);
      }
    }
    return buffer.toString();
  }

  /// Short lists of scalars read better inline: `alpn: ["h3"]`.
  static bool _isInlineList(Object? value) {
    if (value is! List || value.isEmpty) return false;
    if (value.any((item) => item is Map || item is List)) return false;
    return '[${value.map(_yamlScalar).join(', ')}]'.length <= 72;
  }

  static void _emitMap(
    StringBuffer buffer,
    Map<String, Object?> map,
    int level, {
    String? firstPrefix,
  }) {
    var index = 0;
    for (final entry in map.entries) {
      final prefix = index == 0 && firstPrefix != null
          ? firstPrefix
          : _indent(level);
      index++;
      final value = entry.value;
      final isNested = ((value is Map && value.isNotEmpty) ||
              (value is List && value.isNotEmpty)) &&
          !_isInlineList(value);
      if (isNested) {
        buffer.writeln('$prefix${entry.key}:');
        _emitNode(buffer, value, level + 1);
      } else {
        buffer.writeln('$prefix${entry.key}: ${_yamlScalar(value)}');
      }
    }
  }

  static void _emitNode(StringBuffer buffer, Object? node, int level) {
    if (node is Map) {
      _emitMap(buffer, node.cast<String, Object?>(), level);
      return;
    }
    if (node is List) {
      for (final item in node) {
        if (item is Map) {
          _emitMap(
            buffer,
            item.cast<String, Object?>(),
            level + 1,
            firstPrefix: '${_indent(level)}- ',
          );
        } else {
          buffer.writeln('${_indent(level)}- ${_yamlScalar(item)}');
        }
      }
      return;
    }
    buffer.writeln('${_indent(level)}${_yamlScalar(node)}');
  }
}

extension ShareLinkStringExtension on String {
  /// Whether the string carries proxy share links or a raw config, i.e. content
  /// that becomes a local profile instead of a subscription.
  bool get isShareLinkContent {
    final kind = ShareLink.detect(this);
    return kind == ShareLinkContentKind.shareLink ||
        kind == ShareLinkContentKind.yamlConfig;
  }

  /// Whether the string is anything Bettbox knows how to import.
  bool get isProfileContent => ShareLink.isImportable(this);
}
