<?php
include('vendor/autoload.php');
$webauthn = new \mafuth\boimatric\WebAuthn($_SERVER['HTTP_HOST']);

define('USER_DATABASE','users');
if (! file_exists(USER_DATABASE)) {
  if (! @mkdir(USER_DATABASE)) {
    error_log(sprintf('Cannot create user database directory - is the html directory writable by the web server? If not: "mkdir %s; chmod 777 %s"', USER_DATABASE, USER_DATABASE));
    die(sprintf("cannot create %s - see error log", USER_DATABASE));
  }
}
session_start();

function oops($s){
  http_response_code(400);
  echo "{$s}\n";
  exit;
}

function userpath($username){
    $username = str_replace('.', '%2E', $username);
    return sprintf('%s/%s.json', USER_DATABASE, urlencode($username));
}

function getuser($username){
    $user = @file_get_contents(userpath($username));
    if (empty($user)) { oops('user not found'); }
    $user = json_decode($user);
    if (empty($user)) { oops('user not json decoded'); }
    return $user;
}

if($_POST['get'] == "challenge"){
    
    //username or any identifier
    $username = "test";
    $user = getuser($username);

    $j['challenge'] = $webauthn->prepareForLogin($user->webauthnkeys);
}
if($_POST['get'] == "loggin"){
    
    //username or any identifier
    $username = "test";
    $user = getuser($username);
    if (! $webauthn->authenticate($_POST['login'], $user->webauthnkeys)) {
        oops('failed to authenticate with that key');
    }
    $j = 'ok';
}
header('Content-type: application/json');
echo json_encode($j);

