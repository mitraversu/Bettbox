import 'dart:convert';

import 'package:bett_box/common/share_link.dart';
import 'package:flutter_test/flutter_test.dart';

const _uuid = 'bfbfe7fc-bd67-4639-af3d-da59e7f0533e';
const _publicKey = 'XRAYPUBKEYxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx';

String _b64(String value, {bool urlSafe = false}) {
  final encoded = urlSafe
      ? base64Url.encode(utf8.encode(value))
      : base64.encode(utf8.encode(value));
  return encoded.replaceAll('=', '');
}

String _vmess(Map<String, Object?> payload, {bool urlSafe = false}) =>
    'vmess://${_b64(jsonEncode(payload), urlSafe: urlSafe)}';

/// Parses a single link and asserts it produced exactly one node.
Map<String, Object?> _node(String link) {
  final result = ShareLink.parse(link);
  expect(result.failures, isEmpty, reason: link);
  expect(result.proxies, hasLength(1), reason: link);
  return result.proxies.single;
}

void main() {
  group('vmess', () {
    test('websocket over tls', () {
      final link = _vmess({
        'v': '2',
        'ps': '🇭🇰 HK 01 | vmess-ws',
        'add': 'hk.example.com',
        'port': '443',
        'id': _uuid,
        'aid': '0',
        'scy': 'auto',
        'net': 'ws',
        'type': 'none',
        'host': 'cdn.example.com',
        'path': '/ws path',
        'tls': 'tls',
        'sni': 'hk.example.com',
        'alpn': 'h2,http/1.1',
        'fp': 'chrome',
        'ed': '2048',
      });
      expect(
        _node(link),
        <String, Object?>{
          'name': '🇭🇰 HK 01 | vmess-ws',
          'type': 'vmess',
          'server': 'hk.example.com',
          'port': 443,
          'uuid': _uuid,
          'alterId': 0,
          'cipher': 'auto',
          'udp': true,
          'tls': true,
          'servername': 'hk.example.com',
          'client-fingerprint': 'chrome',
          'alpn': ['h2', 'http/1.1'],
          'network': 'ws',
          'ws-opts': {
            'path': '/ws path',
            'headers': {'Host': 'cdn.example.com'},
            'max-early-data': 2048,
            'early-data-header-name': 'Sec-WebSocket-Protocol',
          },
        },
      );
    });

    test('grpc', () {
      final link = _vmess({
        'v': '2',
        'ps': 'grpc node',
        'add': '1.2.3.4',
        'port': '2053',
        'id': _uuid,
        'aid': '0',
        'scy': 'aes-128-gcm',
        'net': 'grpc',
        'path': 'GunService',
        'tls': 'tls',
        'sni': 'a.com',
      });
      final node = _node(link);
      expect(node['network'], 'grpc');
      expect(node['grpc-opts'], {'grpc-service-name': 'GunService'});
      expect(node['cipher'], 'aes-128-gcm');
      expect(node['tls'], true);
    });

    test('h2 splits the host list', () {
      final link = _vmess({
        'v': '2',
        'ps': 'h2 node',
        'add': 'a.com',
        'port': 8443,
        'id': _uuid,
        'aid': 2,
        'scy': 'auto',
        'net': 'h2',
        'host': 'a.com,b.com',
        'path': '/h2',
        'tls': 'tls',
      });
      final node = _node(link);
      expect(node['alterId'], 2);
      expect(node['network'], 'h2');
      expect(node['h2-opts'], {'host': ['a.com', 'b.com'], 'path': '/h2'});
    });

    test('kcp keeps header and seed', () {
      final link = _vmess({
        'v': '2',
        'ps': 'kcp',
        'add': 'a.com',
        'port': 443,
        'id': _uuid,
        'aid': 0,
        'scy': 'auto',
        'net': 'kcp',
        'type': 'srtp',
        'seed': 'secretseed',
      });
      final node = _node(link);
      expect(node['network'], 'mkcp');
      expect(node['mkcp-opts'], {'header': 'srtp', 'seed': 'secretseed'});
      expect(node.containsKey('tls'), false);
    });

    test('reality', () {
      final link = _vmess({
        'v': '2',
        'ps': 'reality',
        'add': 'a.com',
        'port': 443,
        'id': _uuid,
        'aid': 0,
        'scy': 'auto',
        'net': 'tcp',
        'tls': 'reality',
        'pbk': _publicKey,
        'sid': 'abcd1234',
        'fp': 'chrome',
        'sni': 'www.microsoft.com',
      });
      final node = _node(link);
      expect(node['tls'], true);
      expect(node['servername'], 'www.microsoft.com');
      expect(node['client-fingerprint'], 'chrome');
      expect(
        node['reality-opts'],
        {'public-key': _publicKey, 'short-id': 'abcd1234'},
      );
      expect(node.containsKey('network'), false);
    });

    test('accepts url-safe base64 payloads', () {
      final link = _vmess(
        {'v': '2', 'ps': 'urlsafe', 'add': 'a.com', 'port': 443, 'id': _uuid},
        urlSafe: true,
      );
      final node = _node(link);
      expect(node['name'], 'urlsafe');
      expect(node['type'], 'vmess');
    });

    test('falls back to server:port when the remark is empty', () {
      final link = _vmess({
        'v': '2',
        'ps': '',
        'add': 'a.com',
        'port': 80,
        'id': _uuid,
        'aid': 0,
        'scy': 'auto',
        'net': 'tcp',
      });
      expect(_node(link)['name'], 'a.com:80');
    });
  });

  group('vless', () {
    test('reality with vision flow', () {
      const link = 'vless://$_uuid@reality.example.com:443'
          '?encryption=none&security=reality&sni=www.lovense.com&fp=chrome'
          '&pbk=$_publicKey&sid=1234abcd&type=tcp&flow=xtls-rprx-vision'
          '#%F0%9F%87%A9%F0%9F%87%AA%20DE%20%7C%20reality';
      expect(
        _node(link),
        <String, Object?>{
          'name': '🇩🇪 DE | reality',
          'type': 'vless',
          'server': 'reality.example.com',
          'port': 443,
          'uuid': _uuid,
          'udp': true,
          'tls': true,
          'servername': 'www.lovense.com',
          'client-fingerprint': 'chrome',
          'flow': 'xtls-rprx-vision',
          'reality-opts': {
            'public-key': _publicKey,
            'short-id': '1234abcd',
          },
        },
      );
    });

    test('websocket with early data path', () {
      const link = 'vless://$_uuid@1.2.3.4:8443?encryption=none'
          '&security=tls&sni=ws.example.com&type=ws&host=ws.example.com'
          '&path=%2Fvless-ws%3Fed%3D2048&alpn=h2%2Ch3&allowInsecure=1#WS%2Bnode';
      final node = _node(link);
      expect(node['name'], 'WS+node');
      expect(node['skip-cert-verify'], true);
      expect(node['alpn'], ['h2', 'h3']);
      expect(
        node['ws-opts'],
        {
          'path': '/vless-ws?ed=2048',
          'headers': {'Host': 'ws.example.com'},
        },
      );
    });

    test('xhttp', () {
      const link = 'vless://$_uuid@a.com:443?security=tls&type=xhttp'
          '&mode=packet-up&host=x.example.com&path=%2Fxhttp'
          '&xhttpMode=stream-one#xhttp';
      final node = _node(link);
      expect(node['network'], 'xhttp');
      expect(
        node['xhttp-opts'],
        {'path': '/xhttp', 'host': 'x.example.com', 'mode': 'packet-up'},
      );
    });

    test('httpupgrade maps to websocket transport', () {
      const link = 'vless://$_uuid@a.com:2087?security=tls&type=httpupgrade'
          '&host=a.com&path=%2Fupgrade&sni=a.com#upgrade';
      final node = _node(link);
      expect(node['network'], 'ws');
      expect(
        node['ws-opts'],
        {
          'path': '/upgrade',
          'headers': {'Host': 'a.com'},
          'v2ray-http-upgrade': true,
        },
      );
    });

    test('grpc uses the service name', () {
      const link = 'vless://$_uuid@a.com:443?security=tls&type=grpc'
          '&serviceName=grpc-service&sni=a.com#grpc';
      final node = _node(link);
      expect(node['network'], 'grpc');
      expect(node['grpc-opts'], {'grpc-service-name': 'grpc-service'});
    });

    test('bracketed ipv6 server', () {
      const link = 'vless://$_uuid@[2001:db8::1]:443?security=tls'
          '&sni=v6.example.com#ipv6';
      final node = _node(link);
      expect(node['server'], '2001:db8::1');
      expect(node['port'], 443);
      expect(node['servername'], 'v6.example.com');
    });

    test('packet encoding and plain tcp', () {
      const packet = 'vless://$_uuid@a.com:443?security=tls&type=tcp'
          '&packetEncoding=packetaddr#pkt';
      expect(_node(packet)['packet-addr'], true);

      const plain = 'vless://$_uuid@a.com:80?type=tcp#plain';
      final node = _node(plain);
      expect(node['port'], 80);
      expect(node.containsKey('tls'), false);
    });
  });

  group('trojan', () {
    test('websocket with percent encoded password', () {
      const link = 'trojan://p%40ss%3Aword@t.example.com:443?security=tls'
          '&type=ws&host=t.example.com&path=%2Ftrojan-ws&sni=t.example.com'
          '&allowInsecure=0&fp=chrome#Trojan%20WS';
      final node = _node(link);
      expect(node['name'], 'Trojan WS');
      expect(node['password'], 'p@ss:word');
      expect(node['sni'], 't.example.com');
      expect(node['client-fingerprint'], 'chrome');
      expect(node.containsKey('skip-cert-verify'), false);
      expect(
        node['ws-opts'],
        {
          'path': '/trojan-ws',
          'headers': {'Host': 't.example.com'},
        },
      );
    });

    test('plain tcp with peer sni', () {
      const link =
          'trojan://password123@1.2.3.4:443?peer=1.2.3.4&sni=a.com#simple';
      final node = _node(link);
      expect(node['name'], 'simple');
      expect(node['password'], 'password123');
      expect(node['sni'], 'a.com');
    });

    test('grpc', () {
      const link = 'trojan://pwd@a.com:443?type=grpc'
          '&serviceName=trojan-grpc&sni=a.com#t-grpc';
      final node = _node(link);
      expect(node['network'], 'grpc');
      expect(node['grpc-opts'], {'grpc-service-name': 'trojan-grpc'});
    });

    test('keeps plus and stray percent characters in the password', () {
      expect(
        _node('trojan://p+ss+word@a.com:443?sni=a.com#plus')['password'],
        'p+ss+word',
      );
      expect(
        _node('trojan://100%pass@a.com:443#pct')['password'],
        '100%pass',
      );
      expect(
        _node('trojan://p%3Ass%3Aword@a.com:443?sni=a.com#colon')['password'],
        'p:ss:word',
      );
    });
  });

  group('shadowsocks', () {
    test('sip002 with simple-obfs plugin', () {
      final link = 'ss://${_b64('aes-256-gcm:YpaQ4yIjz2ObLw8y7Bsa2A', urlSafe: true)}'
          '@sg.example.com:8388/'
          '?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#SS%20obfs';
      expect(
        _node(link),
        <String, Object?>{
          'name': 'SS obfs',
          'type': 'ss',
          'server': 'sg.example.com',
          'port': 8388,
          'cipher': 'aes-256-gcm',
          'password': 'YpaQ4yIjz2ObLw8y7Bsa2A',
          'udp': true,
          'plugin': 'obfs',
          'plugin-opts': {'mode': 'http', 'host': 'bing.com'},
        },
      );
    });

    test('sip002 with v2ray-plugin flags', () {
      final link = 'ss://${_b64('chacha20-ietf-poly1305:mypassword', urlSafe: true)}'
          '@1.2.3.4:8389/?plugin=v2ray-plugin%3Bmode%3Dwebsocket'
          '%3Bhost%3Dcdn.example.com%3Bpath%3D%2Fray%3Btls#SS%20v2ray';
      final node = _node(link);
      expect(node['plugin'], 'v2ray-plugin');
      expect(
        node['plugin-opts'],
        {
          'mode': 'websocket',
          'host': 'cdn.example.com',
          'path': '/ray',
          'tls': true,
        },
      );
    });

    test('plain node', () {
      final link = 'ss://${_b64('aes-128-gcm:test', urlSafe: true)}'
          '@1.2.3.4:8388#plain-ss';
      final node = _node(link);
      expect(node['cipher'], 'aes-128-gcm');
      expect(node['password'], 'test');
      expect(node.containsKey('plugin'), false);
    });

    test('unencoded method:password authority', () {
      final node = _node('ss://aes-256-cfb:password@1.2.3.4:8388#literal');
      expect(node['cipher'], 'aes-256-cfb');
      expect(node['password'], 'password');
    });

    test('legacy full base64 payload keeps the remark', () {
      final link = 'ss://${_b64('aes-256-cfb:password@1.2.3.4:8388')}#legacy';
      final node = _node(link);
      expect(node['name'], 'legacy');
      expect(node['server'], '1.2.3.4');
      expect(node['port'], 8388);
    });

    test('2022 cipher', () {
      // The password itself is base64 of the raw key bytes 0..15.
      final link =
          'ss://${_b64('2022-blake3-aes-128-gcm:AAECAwQFBgcICQoLDA0ODw')}'
          '@1.2.3.4:8388#ss2022';
      final node = _node(link);
      expect(node['cipher'], '2022-blake3-aes-128-gcm');
      expect(node['password'], 'AAECAwQFBgcICQoLDA0ODw');
    });
  });

  group('shadowsocksr', () {
    test('standard base64 payload', () {
      final payload = 'ssr.example.com:8389:auth_aes128_md5:aes-256-cfb:'
          'tls1.2_ticket_auth:${_b64('passw0rd', urlSafe: true)}'
          '/?obfsparam=${_b64('bing.com', urlSafe: true)}'
          '&protoparam=${_b64('1:64yvk', urlSafe: true)}'
          '&remarks=${_b64('SSR 节点', urlSafe: true)}'
          '&group=${_b64('group', urlSafe: true)}';
      expect(
        _node('ssr://${_b64(payload, urlSafe: true)}'),
        <String, Object?>{
          'name': 'SSR 节点',
          'type': 'ssr',
          'server': 'ssr.example.com',
          'port': 8389,
          'cipher': 'aes-256-cfb',
          'password': 'passw0rd',
          'obfs': 'tls1.2_ticket_auth',
          'protocol': 'auth_aes128_md5',
          'udp': true,
          'obfs-param': 'bing.com',
          'protocol-param': '1:64yvk',
        },
      );
    });
  });

  group('hysteria', () {
    test('v1 keeps auth string and bandwidth', () {
      final link = 'hysteria://h.example.com:443/?protocol=udp'
          '&auth=${_b64('myauth')}&peer=sni.example.com&insecure=1'
          '&upmbps=100&downmbps=200&alpn=h3&fastopen=1#hy1';
      expect(
        _node(link),
        <String, Object?>{
          'name': 'hy1',
          'type': 'hysteria',
          'server': 'h.example.com',
          'port': 443,
          'up': '100',
          'down': '200',
          'auth-str': 'myauth',
          'protocol': 'udp',
          'sni': 'sni.example.com',
          'alpn': ['h3'],
          'skip-cert-verify': true,
          'fast-open': true,
        },
      );
    });

    test('v2 with obfuscation', () {
      const link = 'hysteria2://my%2Fpassword@hy2.example.com:443/?insecure=1'
          '&sni=hy2.example.com&obfs=salamander&obfs-password=obfspwd'
          '&alpn=h3#HY2%20node';
      expect(
        _node(link),
        <String, Object?>{
          'name': 'HY2 node',
          'type': 'hysteria2',
          'server': 'hy2.example.com',
          'password': 'my/password',
          'port': 443,
          'sni': 'hy2.example.com',
          'alpn': ['h3'],
          'obfs': 'salamander',
          'obfs-password': 'obfspwd',
          'skip-cert-verify': true,
        },
      );
    });

    test('hy2 alias', () {
      final node = _node('hy2://pwd@1.2.3.4:443/?sni=a.com#hy2alias');
      expect(node['type'], 'hysteria2');
      expect(node['name'], 'hy2alias');
    });

    test('port hopping passes the range through verbatim', () {
      final node = _node(
        'hysteria2://pwd@a.com:20000-30000/?sni=a.com&mport=20000-30000#hop',
      );
      expect(node['ports'], '20000-30000');
      expect(node.containsKey('port'), false);
    });
  });

  group('tuic', () {
    test('v5 credentials', () {
      const link = 'tuic://$_uuid:tuicpass@tuic.example.com:443/'
          '?sni=tuic.example.com&congestion_control=bbr&alpn=h3%2Ch4'
          '&disable_sni=1&udp_relay_mode=native&allow_insecure=0#TUIC%20node';
      expect(
        _node(link),
        <String, Object?>{
          'name': 'TUIC node',
          'type': 'tuic',
          'server': 'tuic.example.com',
          'port': 443,
          'uuid': _uuid,
          'password': 'tuicpass',
          'sni': 'tuic.example.com',
          'alpn': ['h3', 'h4'],
          'congestion-controller': 'bbr',
          'udp-relay-mode': 'native',
          'disable-sni': true,
        },
      );
    });

    test('v4 token', () {
      final node = _node('tuic://mytoken@tuic.example.com:443/?peer=a.com#tuic4');
      expect(node['token'], 'mytoken');
      expect(node['sni'], 'a.com');
      expect(node.containsKey('uuid'), false);
    });
  });

  group('wireguard', () {
    final privateKey = _b64('a' * 32, urlSafe: true);
    final publicKey = _b64('b' * 32, urlSafe: true);
    final preSharedKey = _b64('c' * 32, urlSafe: true);

    test('warp style link', () {
      final link = 'wireguard://$privateKey@162.159.192.1:2408/'
          '?publickey=$publicKey&allowedips=0.0.0.0/0,::/0&mtu=1280'
          '&reserved=${base64.encode([1, 2, 3])}'
          '&presharedkey=$preSharedKey&workers=2#warp';
      final node = _node(link);
      expect(node['private-key'], base64.encode(utf8.encode('a' * 32)));
      expect(node['public-key'], base64.encode(utf8.encode('b' * 32)));
      expect(node['pre-shared-key'], base64.encode(utf8.encode('c' * 32)));
      expect(node['allowed-ips'], ['0.0.0.0/0', '::/0']);
      expect(node['mtu'], 1280);
      expect(node['workers'], 2);
      expect(node['reserved'], [1, 2, 3]);
      // No local address was given, a deterministic one is derived instead.
      expect(node['ip'], '172.16.2.226');
      expect(_node(link)['ip'], node['ip']);
    });

    test('local addresses are kept as given', () {
      final link = 'wireguard://$privateKey@1.2.3.4:51820/?publickey=$publicKey'
          '&localip=172.16.0.2/24,2606:4700:110:8d48::2/64&reserved=1,2,3'
          '#wg-local';
      final node = _node(link);
      expect(node['ip'], '172.16.0.2/24');
      expect(node['ipv6'], '2606:4700:110:8d48::2/64');
      expect(node['allowed-ips'], ['0.0.0.0/0']);
      expect(node['reserved'], [1, 2, 3]);
    });
  });

  group('other protocols', () {
    test('anytls', () {
      const link = 'anytls://anypassword@anytls.example.com:443/'
          '?sni=anytls.example.com&insecure=1&fp=chrome&alpn=h3#AnyTLS';
      final node = _node(link);
      expect(node['type'], 'anytls');
      expect(node['password'], 'anypassword');
      expect(node['skip-cert-verify'], true);
      expect(node['client-fingerprint'], 'chrome');
    });

    test('socks5', () {
      final node = _node('socks5://user:pass@socks.example.com:1080#socks');
      expect(
        node,
        <String, Object?>{
          'name': 'socks',
          'type': 'socks5',
          'server': 'socks.example.com',
          'port': 1080,
          'udp': true,
          'username': 'user',
          'password': 'pass',
        },
      );
    });

    test('proxy urls are servers, not subscriptions', () {
      final http = _node('http://user:pass@proxy.example.com:8080');
      expect(http['type'], 'http');
      expect(http['name'], 'proxy.example.com:8080');
      expect(http.containsKey('tls'), false);

      final https = _node('https://user:pass@proxy.example.com:8443#HTTPS%20proxy');
      expect(https['type'], 'http');
      expect(https['name'], 'HTTPS proxy');
      expect(https['tls'], true);
      expect(ShareLink.detect('http://user:pass@proxy.example.com:8080'),
          ShareLinkContentKind.shareLink);
    });
  });

  group('detection', () {
    test('subscription addresses', () {
      const url = 'https://sub.example.com/api/v1/client/subscribe?token=abc';
      expect(ShareLink.detect(url), ShareLinkContentKind.subscriptionUrl);
      expect(ShareLink.parse(url).url, url);
      expect(ShareLink.parse('  https://a.com/b  ').url, 'https://a.com/b');
      expect(
        ShareLink.parse('https://user:pass@sub.example.com:8443/sub?token=x').url,
        'https://user:pass@sub.example.com:8443/sub?token=x',
      );
    });

    test('install-config one-click links', () {
      const link = 'clash://install-config'
          '?url=https%3A%2F%2Fsub.example.com%2Fa%3Ftoken%3Dx';
      final result = ShareLink.parse(link);
      expect(result.kind, ShareLinkContentKind.subscriptionUrl);
      expect(result.url, 'https://sub.example.com/a?token=x');
      expect('clash://install-config'.isProfileContent, false);
    });

    test('raw and base64 wrapped configs', () {
      const yaml = 'mixed-port: 7890\n'
          'proxies:\n'
          '  - name: a\n'
          '    type: ss\n'
          '    server: 1.1.1.1\n'
          '    port: 8388\n'
          '    cipher: aes-256-gcm\n'
          '    password: x\n'
          'rules:\n'
          '  - MATCH,DIRECT';
      final raw = ShareLink.parse(yaml);
      expect(raw.kind, ShareLinkContentKind.yamlConfig);
      expect(raw.yaml, yaml);
      expect(raw.hasContent, true);

      final wrapped = ShareLink.parse(base64.encode(utf8.encode(yaml)));
      expect(wrapped.kind, ShareLinkContentKind.yamlConfig);
      expect(wrapped.yaml, yaml);
    });

    test('unknown content', () {
      for (final text in ['', 'hello world', 'not a link', 'test']) {
        expect(ShareLink.detect(text), ShareLinkContentKind.unknown,
            reason: text);
        expect(ShareLink.parse(text).hasContent, false, reason: text);
      }
    });

    test('string helpers', () {
      expect('vless://$_uuid@a.com:443#x'.isShareLinkContent, true);
      expect('vless://$_uuid@a.com:443#x'.isProfileContent, true);
      expect('https://a.com/sub'.isProfileContent, true);
      expect('https://a.com/sub'.isShareLinkContent, false);
      expect('hello'.isProfileContent, false);
      expect(ShareLink.schemeOf('HY2://pwd@a.com:443'), 'hysteria2');
      expect(ShareLink.schemeOf('https://a.com'), null);
    });
  });

  group('bundles', () {
    const vless = 'vless://$_uuid@a.com:443?security=tls&sni=a.com#node-1';
    const trojan = 'trojan://password123@1.2.3.4:443?sni=a.com#simple-trojan';

    test('several links in one blob', () {
      final result = ShareLink.parse('$vless\n$trojan\n$vless\n$trojan');
      expect(result.kind, ShareLinkContentKind.shareLink);
      expect(result.linkCount, 4);
      expect(result.failureCount, 0);
      expect(
        result.proxyNames,
        ['node-1', 'simple-trojan', 'node-1 2', 'simple-trojan 2'],
      );
    });

    test('links embedded in prose', () {
      final result = ShareLink.parse('New node: $vless, share it! ($trojan)');
      expect(result.proxies, hasLength(2));
      expect(result.proxyNames, ['node-1', 'simple-trojan']);
    });

    test('base64 wrapped bundles', () {
      final bundle = base64.encode(utf8.encode('$vless\n$trojan'));
      final result = ShareLink.parse(bundle);
      expect(result.kind, ShareLinkContentKind.shareLink);
      expect(result.proxyNames, ['node-1', 'simple-trojan']);
    });

    test('suggests a profile label', () {
      expect(ShareLink.suggestLabel(ShareLink.parse(vless)), 'node-1');
      expect(
        ShareLink.suggestLabel(ShareLink.parse('$vless\n$trojan')),
        'node-1 +1',
      );
      expect(ShareLink.suggestLabel(ShareLink.parse('hello')), null);
    });
  });

  group('malformed links', () {
    const trojan = 'trojan://password123@1.2.3.4:443?sni=a.com#simple-trojan';

    test('are reported as failures instead of crashing', () {
      for (final link in [
        'vmess://!!!!',
        'vmess://${_b64('not json')}',
        'ss://abc',
        'ssr://${_b64('not-ssr')}',
        'trojan://pass@host',
        'wireguard://x@1.2.3.4:443',
        'vless://uuid@host:notaport',
      ]) {
        final result = ShareLink.parse(link);
        expect(result.kind, ShareLinkContentKind.shareLink, reason: link);
        expect(result.proxies, isEmpty, reason: link);
        expect(result.failureCount, 1, reason: link);
      }
    });

    test('empty scheme payload is not a link at all', () {
      final result = ShareLink.parse('vless://');
      expect(result.kind, ShareLinkContentKind.unknown);
      expect(result.hasContent, false);
    });

    test('a broken link does not sink the valid ones', () {
      final result = ShareLink.parse('vmess://!!!!\n$trojan');
      expect(result.proxies, hasLength(1));
      expect(result.failureCount, 1);
      expect(result.proxyNames, ['simple-trojan']);
    });
  });

  group('buildConfig', () {
    test('produces a minimal usable mihomo config', () {
      const vless = 'vless://$_uuid@a.com:443?security=tls&sni=a.com#node-1';
      const trojan = 'trojan://password123@1.2.3.4:443?sni=a.com#node-2';
      final result = ShareLink.parse('$vless\n$trojan');
      final config = ShareLink.buildConfig(result.proxies);

      expect(config, startsWith('# Generated by Bettbox'));
      expect(config, contains('proxies:'));
      expect(config, contains('- name: "node-1"'));
      expect(config, contains('- name: "node-2"'));
      expect(config, contains('proxy-groups:'));
      expect(config, contains('- name: "PROXY"'));
      expect(config, contains('type: "select"'));
      expect(config, contains('- name: "AUTO"'));
      expect(config, contains('type: "url-test"'));
      expect(config, contains('url: "${ShareLink.defaultTestUrl}"'));
      expect(config, contains('interval: 300'));
      expect(config, contains('rules: ["MATCH,PROXY"]'));
      // Nothing but the imported nodes is configured.
      expect(config.contains('dns:'), false);
      expect(config.contains('tun:'), false);
      expect(config.contains('mixed-port:'), false);
    });

    test('escapes values that need it', () {
      const quoted =
          'vless://$_uuid@a.com:443?security=tls#He%20said%20%22hi%22';
      final config = ShareLink.buildConfig(ShareLink.parse(quoted).proxies);
      expect(config, contains(r'''- name: "He said \"hi\""'''));

      const newline = 'vless://$_uuid@a.com:443?security=tls&type=ws'
          '&path=%2Fpa%0Ath#weird';
      final escaped = ShareLink.buildConfig(ShareLink.parse(newline).proxies);
      expect(escaped, contains(r'''path: "/pa\nth"'''));
    });
  });
}
