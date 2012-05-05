IndieAuth-MediaWiki
===================

MediaWiki authentication extension for [IndieAuth](http://indieauth.com/)


Installation
------------

Add the following to your MediaWiki config file:

```
require_once('extensions/IndieAuth-MediaWiki/IndieAuth.php');
$wgAuth = new IndieAuthPlugin();
```
