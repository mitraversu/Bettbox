import 'dart:async';

import 'package:app_links/app_links.dart';

import 'print.dart';
import 'share_link.dart';

typedef InstallConfigCallBack = void Function(String url);

class LinkManager {
  static LinkManager? _instance;
  late AppLinks _appLinks;
  StreamSubscription? subscription;

  LinkManager._internal() {
    _appLinks = AppLinks();
  }

  Future<void> initAppLinksListen(
    Function(String url) installConfigCallBack,
  ) async {
    commonPrint.log('initAppLinksListen');
    destroy();
    // The raw stream is used on purpose: `vmess://` payloads are base64 and are
    // not valid URIs, parsing them would drop the link.
    subscription = _appLinks.stringLinkStream.listen((link) {
      commonPrint.log('onAppLink: $link');
      final uri = Uri.tryParse(link);
      if (uri != null && uri.host == 'install-config') {
        final parameters = uri.queryParameters;
        final url = parameters['url'];
        if (url != null) {
          installConfigCallBack(url);
        }
        return;
      }
      // Proxy share links handed over by the OS (`vless://`, `ss://`, ...).
      if (link.isShareLinkContent) {
        installConfigCallBack(link);
      }
    });
  }

  void destroy() {
    subscription?.cancel();
    subscription = null;
  }

  factory LinkManager() {
    _instance ??= LinkManager._internal();
    return _instance!;
  }
}

final linkManager = LinkManager();
