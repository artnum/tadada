<?php
namespace TaDaDa;

use PDO;
use Exception;

interface User {
    public function get($userid);
    public function getByUsername($username);
    public function setPassword($userid, $key, $keyopts);
    public function canImpersonate($userid, $impersonateid);
}

class Auth {
    protected $pdo;
    protected $table;
    protected $timeout;
    protected $current_userid;

    const U_CONST_TIME = 100000;
    const HASH = [
        'SHA-256' => ['sha256', 32],
        'SHA-384' => ['sha384', 48],
        'SHA-512' => ['sha512', 64]
    ];
    const SHARE_NONE = 0x00;
    const SHARE_TEMPORARY = 0x01;
    const SHARE_LIMITED_ONCE = 0x02; /* share until used once but with time limit */
    const SHARE_NOT_TIMED = 0x80; /* not used, below time apply, above time don't apply */
    const SHARE_PERMANENT = 0x81;
    const SHARE_PROXY = 0x82; /* to create token for proxy, never expires, not bound to any url, not bound to any user */
    const SHARE_UNLIMITED_ONCE = 0x83; /* share until used once */
    const SHARE_USER_PROXY = 0x84; /* to create token for proxy, never expires, not bound to any url, bound to specific user */

    function __construct(PDO $pdo, String $table = 'tadada_auth') {
        $this->pdo = $pdo;
        $this->table = $table;
        $this->timeout = 86400; // 24h
        $this->current_userid = -1;
    }

    function get_current_userid() {
        return $this->current_userid;
    }

    function find_url($token, $id) {
        $stmt = $this->pdo->prepare(sprintf('SELECT url FROM %s WHERE auth = :token AND urlid = :urlid', $this->table));
        $stmt->bindValue(':urlid', $id, PDO::PARAM_STR);
        $stmt->bindValue(':token', $token, PDO::PARAM_STR);

        if(!$stmt->execute()) { return false; }
        $row = $stmt->fetch();
        if (!$row || empty($row)) { return false; }
        return $row['url'];
    }

    function generate_auth ($userid, $hpw, $cnonce = '', $hash = 'SHA-256') {
        $sign = random_bytes(Auth::HASH[$hash][1]);
        $authvalue = base64_encode(hash_hmac(Auth::HASH[$hash][0], $sign . $cnonce, base64_decode($hpw), true));
        if ($this->add_auth($userid, $authvalue, '', Auth::SHARE_NONE)) {
            return base64_encode($sign);
        }
        return '';
    }

    function generate_share_auth ($userid, $authvalue, $url, $permanent = Auth::SHARE_PERMANENT, $comment = '', $duration = -1, $hash = 'SHA-256') {
        $share_authvalue = $this->get_share_auth($userid, $url, $permanent);
        if (!empty($share_authvalue)) { 
            $this->refresh_auth($share_authvalue);
            return $share_authvalue; 
        }
        $sign = random_bytes(Auth::HASH[$hash][1]);
        $share_authvalue = base64_encode(hash_hmac(Auth::HASH[$hash][0], $sign, base64_decode($authvalue), true));
        if ($this->add_auth($userid, $share_authvalue, $this->prepare_url($url), $permanent, $comment, $duration)) {
            return $share_authvalue;
        }
        return '';
    }

    function get_share_auth($userid, $url, $permanent = Auth::SHARE_PERMANENT) {
        $url = $this->prepare_url($url);
        $urlid = sha1($url);
        $stmt = $this->pdo->prepare(sprintf('SELECT * FROM %s WHERE userid = :userid AND urlid = :urlid AND share = :share', $this->table));
        $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
        $stmt->bindValue(':urlid', $urlid, PDO::PARAM_STR);
        $stmt->bindValue(':share', $permanent, PDO::PARAM_INT);
        $stmt->execute();
        while (($row = $stmt->fetch(PDO::FETCH_ASSOC))) {
            return $row['auth'];
        }
        return '';
    }

    function prepare_url_query($query) {
        $parts = explode('&', $query);
        $parts = array_filter($parts, function ($element) {
            /* access_token parameter is used to pass auth token, so it is not known when getting the shareable token */
            if (strpos($element, 'access_token=') === 0) { return false; }
            return true;
        });
        if (empty($parts)) { return ''; }
        /* sort to allow query begin like ?length=10&time=20 or ?time=20&length=10 */
        sort($parts, SORT_STRING);
        return '?' . implode('&', $parts);
    }

    function prepare_url($url) 
        /* we want tld and first level only. so sublevel can change without
         * invalidating url. protocols is not set as it must be https.
         */{
        $url = filter_var($url, FILTER_VALIDATE_URL);
        $parsed = parse_url($url);
        $host = [];
        $hostParts = explode('.', $parsed['host']);
        array_unshift($host, array_pop($hostParts));
        array_unshift($host, array_pop($hostParts));
        /* needed to allow hosts like localhost or any strange setup */
        $host = array_filter($host, function ($e) { return (empty($e) ? false : true); });
        $url = implode('.', $host);
        if (isset($parsed['path']) && $parsed['path'] !== null) {  $url .= str_replace('//', '/', $parsed['path']); }
        if (isset($parsed['query']) && $parsed['query'] !== null ) { $url .= $this->prepare_url_query($parsed['query']); }

        return str_replace('//', '/', $url);
    }

    function check_auth_header () {
        $url = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http") . "://$_SERVER[HTTP_HOST]$_SERVER[REQUEST_URI]";
        try {
            $token = $this->get_auth_token();
        } catch (Exception $e) {
            return false;
        }
        return $this->check_auth($token, $url);
    }

    function confirm_auth ($authvalue) {
        $pdo = $this->pdo;
        $done = false;
        try {
            $stmt = $pdo->prepare(sprintf('UPDATE %s SET "time" = :time, "confirmed" = 1 WHERE auth = :auth', $this->table));
            $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $stmt->bindValue(':time', time(), PDO::PARAM_INT);

            $done = $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <confirm-auth>, "%s"', $e->getMessage()));
        } finally {
            if ($done) {
                return $this->check_auth_nodelete($authvalue);
            }
            return $done;
        }
    }

    function add_auth ($userid, $authvalue, $url = '', $sharetype = Auth::SHARE_NONE, $comment = '', $duration = -1) {
        $pdo = $this->pdo;
        $done = false;
        $ip = $_SERVER['REMOTE_ADDR'];
        $host = empty($_SERVER['REMOTE_HOST']) ? $ip : $_SERVER['REMOTE_HOST'];
        $ua = !empty($_SERVER['HTTP_USER_AGENT']) ? $_SERVER['HTTP_USER_AGENT'] : '';
        if ($duration === -1) { $duration = $this->timeout; }
        try {
            $urlid = '';
            if ($sharetype !== Auth::SHARE_NONE) {
                $urlid = sha1($url);
            } else {
                $url = '';
            }
            $stmt = $pdo->prepare(sprintf('INSERT INTO %s (userid, auth, started, duration, remotehost, remoteip, useragent, share, urlid, url, comment) VALUES (:uid, :auth, :started, :duration, :remotehost, :remoteip, :useragent, :share, :urlid, :url, :comment);', $this->table));
            $stmt->bindValue(':uid', $userid, PDO::PARAM_STR);
            $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $stmt->bindValue(':started', time(), PDO::PARAM_INT);
            $stmt->bindValue(':duration', $duration, PDO::PARAM_INT);
            $stmt->bindValue(':remotehost', $host, PDO::PARAM_STR);
            $stmt->bindValue(':remoteip', $ip, PDO::PARAM_STR);
            $stmt->bindValue(':useragent', $ua, PDO::PARAM_STR);
            $stmt->bindValue(':share', $sharetype, PDO::PARAM_INT);
            $stmt->bindValue(':urlid', $urlid, PDO::PARAM_STR);
            $stmt->bindValue(':url', $url, PDO::PARAM_STR);
            $stmt->bindValue(':comment', substr($comment, 0, 140), PDO::PARAM_STR);

            $done = $stmt->execute();
        } catch (Exception $e) {
            error_log(sprintf('tadada-auth <add-auth>, "%s"', $e->getMessage()));
        } finally {
            return $done;
        }
    }

    function del_auth ($authvalue) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE auth = :auth', $this->table));
            $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-auth>, "%s"', $e->getMessage()));
        } finally {
            return true;
        }
    }

    private function check_auth_nodelete($authvalue) {
        try {
            $stmt = $this->pdo->prepare(sprintf('SELECT * FROM %s WHERE auth = :auth', $this->table));
            $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $stmt->execute();
            if ($stmt->rowCount() < 1) { throw new Exception('No known auth'); }
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            $this->current_userid = intval($row['userid']);
            return true;
        } catch (Exception $e) {
            error_log(sprintf('tadada-auth <check_auth_nodelete>, "%s"', $e->getMessage()));

        }
    }

    function check_auth ($authvalue, $url = '') {
        $pdo = $this->pdo;
        try {
            $urlid = '';
            if (!empty($url)) { $urlid = sha1($this->prepare_url($url)); }
            $stmt = $pdo->prepare(sprintf('SELECT * FROM %s WHERE auth = :auth', $this->table));
            $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $stmt->execute();
            while (($row = $stmt->fetch(PDO::FETCH_ASSOC))) {
                if ((intval($row['share']) < Auth::SHARE_NOT_TIMED)
                    && (time() - intval($row['time']) > intval($row['duration']))
                ) {
                    /* overtime, delete and next auth token ... if any */
                    $this->del_all_connection_by_id($row['uid']);                    
                    continue;
                }
                
                switch(intval($row['share'])) {
                    default:
                    case Auth::SHARE_NOT_TIMED:
                        break;
                    case Auth::SHARE_NONE:
                        $this->current_userid = intval($row['userid']);
                        return true;
                    case Auth::SHARE_PERMANENT:
                    case Auth::SHARE_TEMPORARY:
                        if ($row['urlid'] !== $urlid) { break; }
                        $this->current_userid = intval($row['userid']);
                        return true;
                        break;
                    case Auth::SHARE_PROXY: // proxy have complete access
                        $this->current_userid = 0;
                        return true;
                    case Auth::SHARE_USER_PROXY:
                        $this->current_userid = intval($row['userid']);
                        break;
                    case Auth::SHARE_UNLIMITED_ONCE:
                    case Auth::SHARE_LIMITED_ONCE:
                        $this->current_userid = intval($row['userid']);
                        $this->del_all_connection_by_id($row['uid']);
                        return true;
                }
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <check-auth>, "%s"', $e->getMessage()));
            return false;
        }
    }

    function refresh_auth($authvalue) {
        $pdo = $this->pdo;
        $done = false;
        $ip = $_SERVER['REMOTE_ADDR'];
        $host = empty($_SERVER['REMOTE_HOST']) ? $ip : $_SERVER['REMOTE_HOST'];
        try {
            $stmt = $pdo->prepare(sprintf('UPDATE %s SET time = :time, remotehost = :remotehost, remoteip = :remoteip WHERE auth = :auth', $this->table));
            $stmt->bindValue(':time', time(), PDO::PARAM_INT);
            $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $stmt->bindValue(':remotehost', $host, PDO::PARAM_STR);
            $stmt->bindValue(':remoteip', $ip, PDO::PARAM_STR);

            $done = $stmt->execute();
        } catch (Exception $e) {
            error_log(sprintf('tadada-auth <refresh-auth>, "%s"', $e->getMessage()));
        } finally {
            return $done;
        }
    }

    function get_id ($authvalue) {
        $pdo = $this->pdo;
        $matching = false;
        try {
            $stmt = $pdo->prepare(sprintf('SELECT * FROM %s WHERE auth = :auth', $this->table));
            $stmt->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $stmt->execute();
            while (($row = $stmt->fetch(PDO::FETCH_ASSOC))) {
                if (
                    (intval($row['share']) !== Auth::SHARE_PERMANENT && intval($row['share']) !== Auth::SHARE_PROXY) 
                    && (time() - intval($row['time']) > intval($row['duration']))
                ) {
                    $this->del_specific_auth($row['auth']);
                } else {
                    $matching = $row['userid'];
                    break;
                }
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <get-id>, "%s"', $e->getMessage()));
        } finally {
            return $matching;
        }
    }

    function get_auth_token () {
        try {
            /* auth can be passed as url */
            if (!empty($_GET['access_token'])) {
                return $_GET['access_token'];
            }
            $authContent = explode(' ', $_SERVER['HTTP_AUTHORIZATION']);
            if (count($authContent) !== 2) { throw new Exception(('Wrong auth header')); }
            return $authContent[1];
        } catch (Exception $e) {
            error_log(sprintf('tadada-auth <get-auth-token>, "%s"', $e->getMessage()));
        }
    }

    function get_active_connection ($userid) {
        $pdo = $this->pdo;
        $connections = [];
        try {
            $stmt = $pdo->prepare(sprintf('SELECT * FROM %s WHERE userid = :userid', $this->table));
            $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
            $stmt->execute();
            while (($row = $stmt->fetch(PDO::FETCH_ASSOC))) {
                if (time() - intVal($row['time'], 10) > $this->timeout) {
                    $del = $pdo->prepare(sprintf('DELETE FROM %s WHERE auth = :auth', $this->table));
                    $del->bindValue(':auth', $row['auth'], PDO::PARAM_STR);
                    $del->execute();
                } else {
                   $auth = '';
                   if (intval($row['share']) === Auth::SHARE_PERMANENT || intval($row['share']) === Auth::SHARE_TEMPORARY) {
                    $auth = $row['auth'];
                   }
                   $connections[] = [
                    'uid' => $row['uid'],
                    'time' => $row['time'],
                    'duration' => $row['duration'],
                    'useragent' => $row['useragent'],
                    'remoteip' => $row['remoteip'],
                    'remotehost' => $row['remotehost'],
                    'share' => $row['share'],
                    'url' => $row['url'],
                    'auth' => $auth,
                    'comment' => $row['comment']
                   ];
                }
            }
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <get-active-connection>, "%s"', $e->getMessage()));
        } finally {
            return $connections;
        }
    }

    function del_specific_auth ($authvalue) {
        try {
            $del = $this->pdo->prepare(sprintf('DELETE FROM %s WHERE auth = :auth', $this->table));
            $del->bindValue(':auth', $authvalue, PDO::PARAM_STR);
            $del->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-specific-auth>, "%s"', $e->getMessage()));
        }
    }            

    function del_specific_connection ($connectionid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE uid = :uid', $this->table));
            $stmt->bindValue(':uid', $connectionid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-specific-connection>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_shares ($userid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE userid = :userid AND (share = 2 OR share = 1)', $this->table));
            $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-shares>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_connections_shares ($userid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE userid = :userid', $this->table));
            $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-connections-shares>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_connections ($userid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE userid = :userid AND share = 0', $this->table));
            $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-connections>, "%s"', $e->getMessage()));
        } 
    }

    function get_auth_by_id ($uid) {
        try {
            $stmt = $this->pdo->prepare(sprintf('SELECT * FROM %s WHERE uid = :uid AND userid = :userid', $this->table));
            $stmt->bindValue(':uid', $uid, PDO::PARAM_INT);
            $stmt->bindValue(':userid', $this->current_userid, PDO::PARAM_INT);
            $stmt->execute();
            return $stmt->fetch(PDO::FETCH_ASSOC);
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <get-auth-by-id>, "%s"', $e->getMessage()));
        }
    }

    function del_all_connection_by_id ($uid) {
        try {
            $stmt = $this->pdo->prepare(sprintf('DELETE FROM %s WHERE uid = :uid AND userid = :userid', $this->table));
            $stmt->bindValue(':uid', $uid, PDO::PARAM_INT);
            $stmt->bindValue(':userid', $this->current_userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('tadada-auth <del-all-connection-by-id>, "%s"', $e->getMessage()));
        }
    }

    function usleep ($time) {
        if ($time > 0) { return usleep($time); }
        return;
    }

    function run ($step, User $user) {        
        try {
            header('Content-Type: application/json', true);
            if (empty($_SERVER['PATH_INFO'])) {
                throw new Exception();
            }
            if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
                throw new Exception('Bad method');
            }
            $body = file_get_contents('php://input');
            $content = [];            
            if (!empty($body)) { $content = json_decode($body, true); }
            switch ($step) {
                default: throw new Exception('Unknown step');
                case 'init':
                    $start = microtime(true);
                    $cnonce = null;
                    $hash = 'SHA-256';
                    if (!empty($content['hash']) && isset(Auth::HASH[$content['hash']])) {
                        $hash = $content['hash'];
                    }
                    if (!empty($content['cnonce'])) { $cnonce = base64_decode($content['cnonce']); }
                    if(empty($content['userid'])) { $this->usleep($this::U_CONST_TIME - (microtime(true) + $start)); throw new Exception(); }
                    $data = $user->get($content['userid']);
                    if (!$data) { $this->usleep($this::U_CONST_TIME - (microtime(true) + $start)); throw new Exception();}
                    $auth = $this->generate_auth($data['id'], $data['key'], $cnonce, $data['algo']);
                    if (empty($auth)) { $this->usleep($this::U_CONST_TIME - (microtime(true) + $start)); throw new Exception(); }
                    $response = [
                        'auth' => $auth,
                        'count' => $data['key_iterations'],
                        'salt' => $data['key_salt'],
                        'userid' => intval($data['id']),
                        'algo' => $data['algo']
                    ];
                    $this->usleep($this::U_CONST_TIME - (microtime(true) + $start));
                    echo json_encode($response);
                    break;
                case 'getshareable':
                    if (empty($content['url'])) { throw new Exception(); }
                case 'check':
                    $start = microtime(true);
                    if (empty($content['auth'])) { $this->usleep($this::U_CONST_TIME - (microtime(true) + $start)); throw new Exception(); }
                    if (!$this->confirm_auth($content['auth'])) { $this->usleep($this::U_CONST_TIME - (microtime(true) + $start)); throw new Exception(); }
                    $this->refresh_auth($content['auth']);
                    if ($step === 'getshareable') {
                        $hash = 'SHA-256';
                        if (!empty($content['hash']) && isset(Auth::HASH[$content['hash']])) {
                            $hash = $content['hash'];
                        }
                        $once = ((isset($content['once'])) ? ($content['once'] == true) : false);
                        $permanent = (isset($content['permanent']) ? ($content['permanent'] == true) : false);
                        $comment = (isset($content['comment']) ? htmlspecialchars(strval($content['comment'])) : '');
                        $duration = (isset($content['duration']) ? intval($content['duration']) : 86400);
                        $userid = $this->get_current_userid();
                        $token = $this->generate_share_auth(
                            $userid,
                            $content['auth'],
                            $content['url'], 
                            $once ? ($permanent ? Auth::SHARE_UNLIMITED_ONCE : Auth::SHARE_LIMITED_ONCE) 
                                  : ($permanent ? Auth::SHARE_PERMANENT : Auth::SHARE_TEMPORARY),
                            $comment,
                            $duration,
                            $hash
                        );
                        $this->confirm_auth($token);
                        if (empty($token)) { $this->usleep($this::U_CONST_TIME - (microtime(true) + $start)); throw new Exception(); }
                        $urlid = sha1($this->prepare_url($content['url']));
                        $this->usleep($this::U_CONST_TIME - (microtime(true) + $start));
                        echo json_encode(['done' => true, 'token' => $token, 'duration' => $duration, 'urlid' => $urlid]);
                        break;
                    }
                    $this->usleep($this::U_CONST_TIME - (microtime(true) + $start));
                    echo json_encode(['done' => true]);
                    break;
                case 'quit':
                    if (empty($content['auth'])) { throw new Exception(); }
                    if (!$this->del_auth($content['auth'])) { throw new Exception(); }
                    echo json_encode(['done' => true]);
                    break;
                case 'userid':
                    if (empty($content['username'])) { throw new Exception(); }
                    $data = $user->getByUsername($content['username']);
                    echo json_encode(['userid' => $data['id']]);
                    break;
                case 'active':
                    $token = $this->get_auth_token();
                    if (!$this->check_auth($token)) { throw new Exception(); }
                    $userid = $this->get_id($token);
                    if (!$userid) { throw new Exception(); }
                    if (empty($content['userid'])) { throw new Exception(); }
                    if (
                        intval($content['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $content['userid'])
                    ) { throw new Exception(); }
                    $connections = $this->get_active_connection($content['userid']);
                    echo json_encode(['userid' => intval($content['userid']), 'connections' => $connections]);
                    break;
                case 'disconnect-all':
                case 'disconnect-share':
                case 'disconnect':
                    $token = $this->get_auth_token();
                    if (!$this->check_auth($token)) { throw new Exception(); }
                    $userid = $this->get_id($token);
                    if (empty($content['userid'])) { throw new Exception(); }
                    if (
                        intval($content['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $content['userid'])
                    ) { throw new Exception(); }
                    switch($step) {
                        case 'disconnect': 
                            if (!$this->del_all_connections($content['userid'])) { throw new Exception(); } 
                            break;
                        case 'disconnect-all':
                            if (!$this->del_all_connections_shares($content['userid'])) { throw new Exception(); }
                            break;
                        case 'disconnect-share':
                            if (!$this->del_all_shares($content['userid'])) { throw new Exception(); }
                            break;
                    }
                    echo json_encode(['userid' => intval($content['userid'])]);
                    break;
                case 'disconnect-by-id':
                    $token = $this->get_auth_token();
                    if (!$this->check_auth($token)) { throw new Exception(); }
                    if (empty($content['uid'])) { throw new Exception(); }
                    $conn = $this->get_auth_by_id($content['uid']);
                    if (!$conn) { throw new Exception(); }
                    $userid = $this->get_id($token);
                    if (!$userid) { throw new Exception(); }
                    if (
                        intval($conn['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $conn['userid'])
                    ) { throw new Exception(); }
                    $success = $this->del_all_connection_by_id($conn['uid']);
                    echo json_encode(['done' => $success]);
                    break;
                case 'setpassword':
                    $token = $this->get_auth_token();
                    if (!$this->check_auth($token)) { throw new Exception(); }
                    $userid = $this->get_id($token);
                    if (!$userid) { throw new Exception(); }
                    if (empty($content['userid'])) { throw new Exception(); }
                    if (empty($content['key'])) { throw new Exception(); }
                    if (empty($content['salt'])) { throw new Exception(); }
                    if (empty($content['iterations'])) { throw new Exception(); }
                    if (empty($content['algo'])) { throw new Exception(); }
                    if (
                        intval($content['userid']) !== intval($userid)
                        && !$user->canImpersonate($userid, $content['userid'])
                    ) { throw new Exception(); }
                    $user->setPassword($content['userid'], $content['key'],
                        ['key_algo' => $content['algo'], 
                        'key_iterations' => $content['iterations'],
                        'key_salt' => $content['salt']
                        ]
                    );
                    echo json_encode(['userid' => intval($content['userid'])]);
                    break;
                case 'whoami':
                    $token = $this->get_auth_token();
                    if (!$this->check_auth($token)) { throw new Exception(); }
                    $stmt = $this->pdo->prepare(sprintf('SELECT "userid" FROM %s WHERE auth = :token', $this->table));
                    $stmt->bindValue(':token', $token, PDO::PARAM_STR);
                    $stmt->execute();
                    if ($stmt->rowCount() !== 1) { throw new Exception(); }
                    $data = $stmt->fetch(PDO::FETCH_ASSOC);
                    echo json_encode(['userid' => intval($data['userid'])]);
                    break;
            }
        } catch (Exception $e) {
            $msg = $e->getMessage();
            if (!empty($msg)) { error_log($msg); }
            echo json_encode(['error' => 'Wrong parameter']); // not specific 
            exit(0);
        }
    }

}