<?php
namespace TaDaDa;

use PDO;
use Exception;

interface User {
    public function get($userid);
    public function getByUsername($username);
    public function setPassword($userid, $key, $keyopts);
}

class Auth {
    protected $pdo;
    protected $table;
    protected $timeout;
    protected $current_userid;

    const HASH_ALGO = 'sha256'; /* fixed as it must match available javascript algo */
    const HASH_ALGO_LENGTH = 32; /* fixed as it must match algo */
    const SHARE_NONE = 0;
    const SHARE_PERMANENT = 1;
    const SHARE_TEMPORARY = 2;
    const SHARE_PROXY = 3; /* to create token for proxy, never expires, not bound to any url, not bound to any user */

    function __construct(PDO $pdo, String $table = 'tadada_auth') {
        $this->pdo = $pdo;
        $this->table = $table;
        $this->timeout = 86400; // 24h
        $this->current_userid = -1;
    }

    function get_current_userid() {
        return $this->current_userid;
    }

    function delete_outdated() {
        $stmt = $this->pdo->prepare(sprintf('DELETE FROM %s WHERE (time + duration) > :time AND share <> :shareproxy AND share <> :sharepermanent', $this->table));
        $stmt->bindValue(':time', time(), PDO::PARAM_INT);
        $stmt->bindValue(':shareproxy', Auth::SHARE_PROXY, PDO::PARAM_INT);
        $stmt->bindValue(':sharepermanent', Auth::SHARE_PERMANENT, PDO::PARAM_INT);
        return $stmt->execute();
    }

    function generate_auth ($userid, $hpw) {
        $sign = random_bytes(Auth::HASH_ALGO_LENGTH);
        $authvalue = base64_encode(hash_hmac(Auth::HASH_ALGO, $sign, base64_decode($hpw), true));
        if ($this->add_auth($userid, $authvalue, '', Auth::SHARE_NONE)) {
            return base64_encode($sign);
        }
        return '';
    }

    function generate_share_auth ($userid, $authvalue, $url, $permanent = Auth::SHARE_PERMANENT, $comment = '', $duration = -1) {
        $share_authvalue = $this->get_share_auth($userid, $url, $permanent);
        if (!empty($share_authvalue)) { 
            $this->refresh_auth($share_authvalue);
            return $share_authvalue; 
        }
        $sign = random_bytes(Auth::HASH_ALGO_LENGTH);
        $share_authvalue = base64_encode(hash_hmac(Auth::HASH_ALGO, $sign, base64_decode($authvalue), true));
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
        /* sort to allow query begin like ?length=10&time=20 or ?time=20&length=10 */
        sort($parts, SORT_STRING);
        return implode('&', $parts);
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
        if (isset($parsed['query']) && $parsed['query'] !== null ) { $url .= '?' . $this->prepare_url_query($parsed['query']); }

        return $url;
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
            error_log(sprintf('kaal-auth <confirm-auth>, "%s"', $e->getMessage()));
        } finally {
            if ($done) {
                return $this->check_auth($authvalue);
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
            error_log(sprintf('kaal-auth <add-auth>, "%s"', $e->getMessage()));
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
            error_log(sprintf('kaal-auth <del-auth>, "%s"', $e->getMessage()));
        } finally {
            return true;
        }
    }

    function check_auth ($authvalue, $url = '') {
        $pdo = $this->pdo;
        $matching = false;
        try {
            $urlid = '';
            if (!empty($url)) { $urlid = sha1($this->prepare_url($url)); }
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
                    if (intval($row['share']) === Auth::SHARE_PROXY) {
                        $matching = true;
                        $this->current_userid = 0;
                        break;
                    }
                    if (intval($row['share']) !== Auth::SHARE_NONE && $row['urlid'] !== $urlid) {
                        break;
                    }
                    $matching = true;
                    $this->current_userid = $row['userid'];
                    break;
                }
            }
        } catch(Exception $e) {
            error_log(sprintf('kaal-auth <check-auth>, "%s"', $e->getMessage()));
        } finally {
            return $matching;
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
            error_log(sprintf('kaal-auth <refresh-auth>, "%s"', $e->getMessage()));
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
            error_log(sprintf('kaal-auth <get-id>, "%s"', $e->getMessage()));
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
            error_log(sprintf('kaal-auth <get-auth-token>, "%s"', $e->getMessage()));
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
            error_log(sprintf('kaal-auth <get-active-connection>, "%s"', $e->getMessage()));
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
            error_log(sprintf('kaal-auth <del-specific-auth>, "%s"', $e->getMessage()));
        }
    }            

    function del_specific_connection ($connectionid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE uid = :uid', $this->table));
            $stmt->bindValue(':uid', $connectionid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('kaal-auth <del-specific-connection>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_shares ($userid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE userid = :userid AND (share = 2 OR share = 1)', $this->table));
            $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('kaal-auth <del-all-shares>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_connections_shares ($userid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE userid = :userid', $this->table));
            $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('kaal-auth <del-all-connections-shares>, "%s"', $e->getMessage()));
        } 
    }

    function del_all_connections ($userid) {
        $pdo = $this->pdo;
        try {
            $stmt = $pdo->prepare(sprintf('DELETE FROM %s WHERE userid = :userid AND share = 0', $this->table));
            $stmt->bindValue(':userid', $userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('kaal-auth <del-all-connections>, "%s"', $e->getMessage()));
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
            error_log(sprintf('kaal-auth <get-auth-by-id>, "%s"', $e->getMessage()));
        }
    }

    function del_all_connection_by_id ($uid) {
        try {
            $stmt = $this->pdo->prepare(sprintf('DELETE FROM %s WHERE uid = :uid AND userid = :userid', $this->table));
            $stmt->bindValue(':uid', $uid, PDO::PARAM_INT);
            $stmt->bindValue(':userid', $this->current_userid, PDO::PARAM_INT);
            return $stmt->execute();
        } catch(Exception $e) {
            error_log(sprintf('kaal-auth <del-all-connection-by-id>, "%s"', $e->getMessage()));
        }
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
            $content = json_decode(file_get_contents('php://input'), true);
            switch ($step) {
                default: throw new Exception('Unknown step');
                case 'init':
                    $this->delete_outdated(); // on init we delete outdated connection
                    if(empty($content['userid'])) { throw new Exception(); }
                    $data = $user->get($content['userid']);
                    if (!$data) { throw new Exception();}
                    $auth = $this->generate_auth($data['id'], $data['key']);
                    if (empty($auth)) { throw new Exception(); }
                    $response = [
                        'auth' => $auth,
                        'count' => $data['key_iterations'],
                        'salt' => $data['key_salt'],
                        'userid' => intval($data['id'])
                    ];
                    echo json_encode($response);
                    break;
                case 'getshareable':
                    if (empty($content['url'])) { throw new Exception(); }
                case 'check':
                    if (empty($content['auth'])) { throw new Exception(); }
                    if (!$this->confirm_auth($content['auth'])) { throw new Exception(); }
                    $this->refresh_auth($content['auth']);
                    if ($step === 'getshareable') {
                        $permanent = (isset($content['permanent']) ? ($content['permanent'] == true) : false);
                        $comment = (isset($content['comment']) ? htmlspecialchars(strval($content['comment'])) : '');
                        $duration = (isset($content['duration']) ? intval($content['duration']) : 86400);
                        $userid = $this->get_current_userid();
                        $token = $this->generate_share_auth(
                            $userid,
                            $content['auth'],
                            $content['url'], 
                            $permanent ? Auth::SHARE_PERMANENT : Auth::SHARE_TEMPORARY,
                            $comment,
                            $duration
                        );
                        $this->confirm_auth($token);
                        if (empty($token)) { throw new Exception(); }
                        echo json_encode(['done' => true, 'token' => $token, 'duration' => $duration]);
                        break;
                    }
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
                    if (empty($content['userid'])) { throw new Exception(); }
                    $stmt =$this->pdo->prepare('SELECT "person_id", "person_level" FROM "person" WHERE "person_id" = :id');
                    $stmt->bindValue(':id', intval($userid), PDO::PARAM_INT);
                    $stmt->execute();
                    if ($stmt->rowCount() !== 1) { throw new Exception(); }
                    $data = $stmt->fetch(PDO::FETCH_ASSOC);
                    if (intval($data['person_level']) > 16) { 
                        if (intval($data['person_id']) !== intval($content['userid'])) {
                            throw new Exception(); 
                        }
                    }
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
                    $stmt =$this->pdo->prepare('SELECT "person_id", "person_level" FROM "person" WHERE "person_id" = :id');
                    $stmt->bindValue(':id', intval($userid), PDO::PARAM_INT);
                    $stmt->execute();
                    if ($stmt->rowCount() !== 1) { throw new Exception(); }
                    $data = $stmt->fetch(PDO::FETCH_ASSOC);
                    if (intval($data['person_level']) > 16) { 
                        if (intval($data['person_id']) !== intval($content['userid'])) {
                            throw new Exception(); 
                        }
                    }
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
                    $success = $this->del_all_connection_by_id($conn['uid']);
                    echo json_encode(['done' => $success]);
                    break;
            }
        } catch (Exception $e) {
            $msg = $e->getMessage();
            error_log(var_export($e, true));
            if (empty($msg)) { $msg = 'Wrong parameter'; }
            echo json_encode(['error' => $msg]);
            exit(0);
        }
    }

}