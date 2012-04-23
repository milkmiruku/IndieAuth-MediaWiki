<?php

// This program is free software: you can redistribute it and/or modify it
// under the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 2 of the License, or (at your option)
// any later version.
//
// This program is distributed in the hope that it will be useful, but WITHOUT
// ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
// FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
// more details.
//
// You should have received a copy of the GNU General Public License along with
// this program.  If not, see <http://www.gnu.org/licenses/>.
//
// Copyright 2012 Aaron Parecki

error_reporting(E_ALL);

//Extension credits that show up on Special:Version
$wgExtensionCredits['other'][] = array(
        'name' => 'IndieAuthPlugin',
        'version' => '0.1.0',
        'author' => array('Aaron Parecki'),
        'url' => 'https://github.com/aaronpk/IndieAuth-MediaWiki',
        'description' => 'Sign users in using the IndieAuth protocol.',
);
 

// Override the login form with our own
$wgHooks['UserLoginForm'][] = 'IndieAuthPlugin::loginForm';

// Prevent creating accounts
$wgGroupPermissions['*']['createaccount'] = false;

// The Auth_remoteuser class is an AuthPlugin so make sure we have this included.
require_once('AuthPlugin.php');

// Set up the special page for handling the callback
$wgSpecialPages['IndieAuth'] = 'mwSpecialIndieAuth';



class mwSpecialIndieAuth extends SpecialPage
{
  function __construct()
  {
    SpecialPage::SpecialPage('IndieAuth');
  }
  
  function execute()
  {
    global $wgOut, $wgAction, $wgRequest;

    $wgOut->setPageTitle('IndieAuth');
    
    if(isset($_GET['token']))
    {
      $domain = IndieAuthPlugin::indieAuthDomainFromToken($_GET['token']);
      $username = IndieAuthPlugin::getCanonicalName($domain);

      if($domain) {
        $id = User::idFromName($username);
        if (!$id) {
            $user = User::newFromName($username);
            $user->setRealName($domain);
            /* No account with this name found, so create one */
            $user->addToDatabase();
            #$user->setPassword(User::randomPassword());
            $user->setToken();
        } else {
            $user = User::newFromId($id);
            $user->loadFromId();
        }

        $user->setCookies();
        $user->saveSettings();

        if(class_exists('NerdhausBot')) {
          $N = new NerdhausBot('logs');
          $N->Send('[mediawiki] New IndieAuth login: ' . $domain);
        }
      }

      if($_GET['returnto']) {
        $mReturnTo = $_GET['returnto'];
        $mReturnToQuery = @$_GET['returntoquery'];
        $titleObj = Title::newFromText( $mReturnTo );
        if ( !$titleObj instanceof Title ) {
          $titleObj = Title::newMainPage();
        }
        $redirectUrl = $titleObj->getFullURL( $mReturnToQuery );
        global $wgSecureLogin;
        if( $wgSecureLogin && !$this->mStickHTTPS ) {
          $redirectUrl = preg_replace( '/^https:/', 'http:', $redirectUrl );
        }
        $wgOut->redirect( $redirectUrl );
      } else {
        header('Location: /');
      }
    }
    else
    {
      $wgOut->addHTML('<a href="http://' . $_SERVER['SERVER_NAME'] . '/Special:UserLogin">Log In</a>');
    }
  }
}


class IndieAuthPlugin extends AuthPlugin {

  public static function loginForm(&$template) {
    // Replace the default login form with our own
    $data = $template->data;
    $template = new IndieAuthLoginTemplate();
    $template->data = $data;
    return TRUE;
  }

  /**
   * Check whether there exists a user account with the given name.
   * The name will be normalized to MediaWiki's requirements, so
   * you might need to munge it (for instance, for lowercase initial
   * letters).
   *
   * @param string $username
   * @return bool
   * @access public
   */
  function userExists( $username ) {
    return true;
  }

  /**
   * Check if a username+password pair is a valid login.
   * The name will be normalized to MediaWiki's requirements, so
   * you might need to munge it (for instance, for lowercase initial
   * letters).
   *
   * @param string $username
   * @param string $password
   * @return bool
   * @access public
   */
    function authenticate($username, $password) {
      $titleObj = Title::newFromText('Special:IndieAuth');

      $redirect_uri = $titleObj->getFullURL(array_key_exists('returnto', $_GET) ? 'returnto='.$_GET['returnto'] : FALSE);

      header('Location: http://indieauth.com/auth?me=' . strtolower($username) . '&redirect_uri=' . urlencode($redirect_uri));
      die();
    }

  /**
   * Modify options in the login template.
   *
   * @param UserLoginTemplate $template
   * @access public
   */
  function modifyUITemplate( &$template ) {
    $template->set('usedomain', false );
    $template->set('useemail', false);      // Disable the mail new password box.
    $template->set('create', false);        // Remove option to create new accounts from the wiki.
  }

  /**
   * Check to see if the specific domain is a valid domain.
   *
   * @param string $domain
   * @return bool
   * @access public
   */
  function validDomain( $domain ) {
    # We ignore domains, so erm, yes?
    return true;
  }

  /**
   * When a user logs in, optionally fill in preferences and such.
   * For instance, you might pull the email address or real name from the
   * external user database.
   *
   * The User object is passed by reference so it can be modified; don't
   * forget the & on your function declaration.
   *
   * @param User $user
   * @access public
   */
  function updateUser( &$user ) {
    return;
  }

  /**
   * Return true if the wiki should create a new local account automatically
   * when asked to login a user who doesn't exist locally but does in the
   * external auth database.
   *
   * If you don't automatically create accounts, you must still create
   * accounts in some way. It's not possible to authenticate without
   * a local account.
   *
   * This is just a question, and shouldn't perform any actions.
   *
   * @return bool
   * @access public
   */
  function autoCreate() {
          return true;
  }


  /**
   * Can users change their passwords?
   *
   * @return bool
   */
  function allowPasswordChange() {
          # We can't change users system passwords
          return false;
  }

  /**
   * Set the given password in the authentication database.
   * Return true if successful.
   *
   * @param string $password
   * @return bool
   * @access public
   */
  function setPassword( $password ) {
          # We can't change users system passwords
          return false;
  }

  /**
   * Update user information in the external authentication database.
   * Return true if successful.
   *
   * @param User $user
   * @return bool
   * @access public
   */
  function updateExternalDB( $user ) {
          # We can't change users details
          return false;
  }

  /**
   * Check to see if external accounts can be created.
   * Return true if external accounts can be created.
   * @return bool
   * @access public
   */
  function canCreateAccounts() {
          # We can't create accounts
          return false;
  }

  /**
   * Add a user to the external authentication database.
   * Return true if successful.
   *
   * @param User $user
   * @param string $password
   * @return bool
   * @access public
   */
  function addUser( $user, $password ) {
          # We can't create accounts
          return false;
  }


  /**
   * Return true to prevent logins that don't authenticate here from being
   * checked against the local database's password fields.
   *
   * This is just a question, and shouldn't perform any actions.
   *
   * @return bool
   * @access public
   */
  function strict() {
          # Only allow authentication from system database
          return true;
  }

  /**
   * When creating a user account, optionally fill in preferences and such.
   * For instance, you might pull the email address or real name from the
   * external user database.
   *
   * The User object is passed by reference so it can be modified; don't
   * forget the & on your function declaration.
   *
   * @param User $user
   * @access public
   */
  function initUser(&$user) {
          # We do everything in updateUser
  }

 
  /**
   * Normalize user names to the MediaWiki standard to prevent duplicate
   * accounts.
   *
   * @param $username String: username.
   * @return string
   * @public
   */
  function getCanonicalName($username) {
    // lowercase the username
    $username = strtolower($username);
    // remove the 'http' on front
    $username = preg_replace('|^https?://|', '', $username);
    // remove trailing slash
    $username = trim($username, '/');
    // replace / with _
    $username = str_replace('/', '_', $username);
    $username = ucfirst($username);
    return $username;
  }

  function indieAuthDomainFromToken($token) {
    $ch = curl_init('http://indieauth.com/session?token=' . $token);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);
    $response = curl_exec($ch);
    if(!$response) {
      // error
      return FALSE;
    }
    $data = json_decode($response);
    if(!$data) {
      // error
      return FALSE;
    }
    if(!property_exists($data, 'me')) {
      // error
      return FALSE;
    }
    return $data->me;
  }
   
}
 
 


class IndieAuthLoginTemplate extends QuickTemplate {
  function execute() {
    if( @$this->data['message'] ) {
?>
  <div class="<?php $this->text('messagetype') ?>box">
    <?php if ( $this->data['messagetype'] == 'error' ) { ?>
      <strong><?php $this->msg( 'loginerror' )?></strong><br />
    <?php } ?>
    <?php $this->html('message') ?>
  </div>
  <div class="visualClear"></div>
<?php } ?>

<div id="loginstart"><?php $this->msgWiki( 'loginstart' ); ?></div>
<div id="userloginForm">
<form name="userlogin" method="post" action="<?php $this->text('action') ?>">
  <h2><?php $this->msg('login') ?></h2>
  <p id="userloginlink"><?php $this->html('link') ?></p>
  <?php $this->html('header'); /* pre-table point for form plugins... */ ?>
  <div id="userloginprompt"><?php  $this->msgWiki('loginprompt') ?></div>
  <?php if( @$this->haveData( 'languages' ) ) { ?><div id="languagelinks"><p><?php $this->html( 'languages' ); ?></p></div><?php } ?>
  <table>
    <tr>
      <td class="mw-label"><label for='wpName1'>Your Domain</label></td>
      <td class="mw-input">
        <?php
      echo Html::input( 'wpName', @$this->data['name'], 'text', array(
        'class' => 'loginText',
        'id' => 'wpName1',
        'tabindex' => '1',
        'size' => '20',
        'required'
        # Can't do + array( 'autofocus' ) because + for arrays in PHP
        # only works right for associative arrays!  Thanks, PHP.
      ) + ( @$this->data['name'] ? array() : array( 'autofocus' => '' ) ) ); ?>

      </td>
    </tr>
    <tr>
      <td></td>
      <td class="mw-submit">
        <?php
          echo Html::input( 'wpLoginAttempt', wfMsg( 'login' ), 'submit', array(
            'id' => 'wpLoginAttempt',
            'tabindex' => '9'
          ) );
        ?>
      </td>
    </tr>
  </table>
  <input type="hidden" name="wpPassword" value="********" id="wpPassword1" />

<?php if( @$this->haveData( 'uselang' ) ) { ?><input type="hidden" name="uselang" value="<?php $this->text( 'uselang' ); ?>" /><?php } ?>
<?php if( @$this->haveData( 'token' ) ) { ?><input type="hidden" name="wpLoginToken" value="<?php $this->text( 'token' ); ?>" /><?php } ?>
</form>
</div>
<div id="loginend"><?php $this->msgWiki( 'loginend' ); ?></div>
<?php

  }
}


