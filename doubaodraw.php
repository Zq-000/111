<?php require_once __DIR__ . '/../common/security/api_auth.php';
// 设置响应头为JSON格式
header('Content-Type: application/json');

// AWS Signature V4 签名类
class VolcanoSigner {
    private $accessKey;
    private $secretKey;
    private $region;
    private $service;
    private $date;
    private $method;
    private $url;
    private $headers;
    private $payload;
    
    const ALGORITHM = 'AWS4-HMAC-SHA256';
    const V4_IDENTIFIER = 'aws4_request';
    const DATE_HEADER = 'X-Amz-Date';
    const TOKEN_HEADER = 'x-amz-security-token';
    const CONTENT_SHA256_HEADER = 'X-Amz-Content-Sha256';
    const K_DATE_PREFIX = 'AWS4';
    
    public function __construct($accessKey, $secretKey, $date, $region = 'cn-north-1') {
        $this->accessKey = $accessKey;
        $this->secretKey = $secretKey;
        $this->region = $region;
        $this->service = 'imagex';
        $this->date = $date;
    }
    
    public function setRequest($method, $url, $headers, $payload = null) {
        $this->method = strtoupper($method);
        $this->url = $url;
        $this->headers = $headers;
        $this->payload = $payload;
        return $this;
    }
    
    private function hmacSha256($key, $msg) {
        return hash_hmac('sha256', $msg, $key, true);
    }
    
    private function getSigningKey() {
        $kSecret = self::K_DATE_PREFIX . $this->secretKey;
        $kDate = $this->hmacSha256($kSecret, substr($this->date, 0, 8));
        $kRegion = $this->hmacSha256($kDate, $this->region);
        $kService = $this->hmacSha256($kRegion, $this->service);
        $kSigning = $this->hmacSha256($kService, self::V4_IDENTIFIER);
        return $kSigning;
    }
    
    private function credentialString() {
        $p1 = substr($this->date, 0, 8);
        return $p1 . '/' . $this->region . '/' . $this->service . '/' . self::V4_IDENTIFIER;
    }
    
    private function canonicalString() {
        $parsedUrl = parse_url($this->url);
        $path = $parsedUrl['path'] ?? '/';
        $query = $parsedUrl['query'] ?? '';
        
        $p1 = $this->method;
        $p2 = $path;
        $p3 = $query ? $this->sortQueryParams($query) : '';
        $p4 = $this->canonicalHeaders() . "\n";
        $p5 = $this->signedHeaders();
        $p6 = $this->hexEncodedBodyHash();
        
        return $p1 . "\n" . $p2 . "\n" . $p3 . "\n" . $p4 . "\n" . $p5 . "\n" . $p6;
    }
    
    private function sortQueryParams($query) {
        $params = explode('&', $query);
        sort($params);
        return implode('&', $params);
    }
    
    private function canonicalHeaders() {
        $headers = [];
        foreach ($this->headers as $key => $value) {
            $headers[strtolower(trim($key))] = trim($value);
        }
        
        ksort($headers);
        
        $canonicalLines = [];
        foreach ($headers as $key => $value) {
            if ($value !== '') {
                $canonicalLines[] = $key . ':' . $value;
            }
        }
        
        return implode("\n", $canonicalLines);
    }
    
    private function signedHeaders() {
        $headers = [];
        foreach ($this->headers as $key => $value) {
            $lowerKey = strtolower($key);
            if (strpos($lowerKey, 'x-amz-') === 0) {
                $headers[] = $lowerKey;
            }
        }
        sort($headers);
        return implode(';', $headers);
    }
    
    private function hexEncodedBodyHash() {
        if (isset($this->headers[self::CONTENT_SHA256_HEADER])) {
            return $this->headers[self::CONTENT_SHA256_HEADER];
        }
        
        if ($this->payload === null) {
            return hash('sha256', '');
        }
        
        if (is_string($this->payload)) {
            return hash('sha256', $this->payload);
        }
        
        return hash('sha256', '');
    }
    
    private function stringToSign() {
        $p1 = self::ALGORITHM;
        $p2 = $this->date;
        $p3 = $this->credentialString();
        $canonicalRequest = $this->canonicalString();
        $p4 = hash('sha256', $canonicalRequest);
        
        return $p1 . "\n" . $p2 . "\n" . $p3 . "\n" . $p4;
    }
    
    private function signature() {
        $signingKey = $this->getSigningKey();
        $stringToSign = $this->stringToSign();
        return hash_hmac('sha256', $stringToSign, $signingKey);
    }
    
    public function addAuthorization() {
        $p1 = self::ALGORITHM;
        $p2 = ' Credential=';
        $p3 = $this->accessKey;
        $p4 = '/';
        $p5 = $this->credentialString();
        $p6 = ', SignedHeaders=';
        $p7 = $this->signedHeaders();
        $p8 = ', Signature=';
        $p9 = $this->signature();
        
        $authorization = $p1 . $p2 . $p3 . $p4 . $p5 . $p6 . $p7 . $p8 . $p9;
        
        $this->headers['Authorization'] = $authorization;
        return $this->headers;
    }
}

// STS Token 管理类
class STSTokenManager {
    private $cookies;
    private $tokenFile = 'STSToken.json';
    
    public function __construct($cookies) {
        $this->cookies = $cookies;
    }
    
    public function prepareUpload() {
        $url = "https://www.doubao.com/alice/resource/prepare_upload?";
        
        $cookieString = '';
        foreach ($this->cookies as $name => $value) {
            $cookieString .= $name . '=' . $value . '; ';
        }
        $cookieString = rtrim($cookieString, '; ');
        
        $headers = [
            "Host: www.doubao.com",
            "Connection: keep-alive",
            "Agw-Js-Conv: str",
            "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36 Edg/138.0.0.0",
            "Accept: application/json, text/plain, */*",
            "Content-Type: application/json",
            "Origin: https://www.doubao.com",
            "Referer: https://www.doubao.com/chat",
            "Cookie: " . $cookieString
        ];
        
        $data = [
            "tenant_id" => "5",
            "scene_id" => "5",
            "resource_type" => 2,
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($httpCode !== 200) {
            throw new Exception("Failed to get STS token. HTTP code: $httpCode");
        }
        
        $result = json_decode($response, true);
        if (!isset($result['code']) || $result['code'] !== 0) {
            throw new Exception("Failed to get STS token: " . ($result['message'] ?? 'Unknown error'));
        }
        
        return $result;
    }
    
    public function getSTSToken($refresh = false) {
        if (file_exists($this->tokenFile)) {
            $data = json_decode(file_get_contents($this->tokenFile), true);
            if (time() - $data['time'] < 60 * 58 && !$refresh) {
                return $data['STSToken'];
            }
        }
        
        $STSToken = $this->prepareUpload();
        
        $data = [
            'STSToken' => $STSToken,
            'time' => time()
        ];
        
        file_put_contents($this->tokenFile, json_encode($data, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT));
        
        return $STSToken;
    }
}

// 辅助函数：生成 UUID v4
function generateUUIDv4() {
    return sprintf('%04x%04x-%04x-%04x-%04x-%04x%04x%04x',
        mt_rand(0, 0xffff), mt_rand(0, 0xffff),
        mt_rand(0, 0xffff),
        mt_rand(0, 0x0fff) | 0x4000,
        mt_rand(0, 0x3fff) | 0x8000,
        mt_rand(0, 0xffff), mt_rand(0, 0xffff), mt_rand(0, 0xffff)
    );
}

// 生成随机字符串
function generateRandomString($length = 8) {
    $characters = 'abcdefghijklmnopqrstuvwxyz0123456789';
    $result = '';
    for ($i = 0; $i < $length; $i++) {
        $result .= $characters[mt_rand(0, strlen($characters) - 1)];
    }
    return $result;
}

// 下载图片函数
function downloadImage($url) {
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_BINARYTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_HEADER, false);
    
    $imageData = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $contentLength = curl_getinfo($ch, CURLINFO_CONTENT_LENGTH_DOWNLOAD);
    curl_close($ch);

    if ($httpCode != 200) {
        throw new Exception("Failed to download image. HTTP code: $httpCode");
    }
    
    if ($contentLength > 0 && strlen($imageData) != $contentLength) {
        throw new Exception("Download incomplete: expected $contentLength bytes, got " . strlen($imageData));
    }
    
    return $imageData;
}

// 计算 CRC32
function calculateCrc32($data) {
    $crc = hash('crc32b', $data);
    return $crc;
}

// 生成随机文件名
function generateRandomFileName() {
    $randomPart = bin2hex(random_bytes(8));
    return $randomPart . '_' . time() . '.jpg';
}

// 上传图片到豆包（使用自动签名）
function uploadToDoubao($imageData, $cookies) {
    // 获取 STS Token
    $tokenManager = new STSTokenManager($cookies);
    $STSToken = $tokenManager->getSTSToken();
    
    if (!isset($STSToken['data'])) {
        throw new Exception("Invalid STS token response");
    }
    
    $uploadHost = $STSToken['data']['upload_host'];
    $serviceId = $STSToken['data']['service_id'];
    $authToken = $STSToken['data']['upload_auth_token'];
    
    // 步骤1: ApplyImageUpload
    $applyUrl = "https://" . $uploadHost . "/?Action=ApplyImageUpload&Version=2018-08-01&ServiceId=" . $serviceId . "&NeedFallback=true&FileSize=" . strlen($imageData) . "&FileExtension=.jpg&s=" . generateRandomString();
    
    $utcTime = gmdate('Ymd\THis\Z');
    $applyHeaders = [
        'X-Amz-Date' => $utcTime,
        'x-amz-security-token' => $authToken['session_token'],
    ];
    
    $signer = new VolcanoSigner($authToken['access_key'], $authToken['secret_key'], $utcTime);
    $applyHeaders = $signer->setRequest('GET', $applyUrl, $applyHeaders)->addAuthorization();
    
    // 发送 ApplyImageUpload 请求
    $formattedHeaders = [];
    foreach ($applyHeaders as $key => $value) {
        $formattedHeaders[] = $key . ': ' . $value;
    }
    $formattedHeaders = array_merge($formattedHeaders, [
        'Host: ' . $uploadHost,
        'Connection: keep-alive',
        'User-Agent: Mozilla/5.0 (Linux; Android 15; V2338A Build/AP3A.240905.015.A2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36',
        'Accept: */*',
        'Origin: https://www.doubao.com',
        'Referer: https://www.doubao.com/',
    ]);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $applyUrl);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $formattedHeaders);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    
    $applyResponse = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception("ApplyImageUpload failed: HTTP code $httpCode");
    }
    
    $applyData = json_decode($applyResponse, true);
    if (isset($applyData['Error'])) {
        throw new Exception("ApplyImageUpload error: " . $applyData['Error']['Message']);
    }
    
    $uploadAddress = $applyData['Result']['UploadAddress'];
    $storeInfo = $uploadAddress['StoreInfos'][0];
    $storeUri = $storeInfo['StoreUri'];
    $storeAuth = $storeInfo['Auth'];
    $uploadHosts = $uploadAddress['UploadHosts'][0];
    $sessionKey = $uploadAddress['SessionKey'];
    
    // 步骤2: 实际上传图片
    $uploadUrl = "https://" . $uploadHosts . "/upload/v1/" . $storeUri;
    $crc32 = calculateCrc32($imageData);
    
    $uploadHeaders = [
        'Host: ' . $uploadHosts,
        'Connection: keep-alive',
        'Authorization: ' . $storeAuth,
        'Content-CRC32: ' . $crc32,
        'User-Agent: Mozilla/5.0 (Linux; Android 15; V2338A Build/AP3A.240905.015.A2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36',
        'Content-Type: application/octet-stream',
        'Content-Disposition: attachment; filename="undefined"',
        'Accept: */*',
        'Origin: https://www.doubao.com',
        'Referer: https://www.doubao.com/',
    ];
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $uploadUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $imageData);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $uploadHeaders);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    
    $uploadResult = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    $uploadData = json_decode($uploadResult, true);
    if (!isset($uploadData['code']) || $uploadData['code'] != 2000) {
        throw new Exception("Upload failed: " . ($uploadData['message'] ?? 'Unknown error'));
    }
    
    // 步骤3: CommitImageUpload
    $commitUrl = "https://" . $uploadHost . "/?Action=CommitImageUpload&Version=2018-08-01&ServiceId=" . $serviceId;
    $commitData = '{"SessionKey":"' . $sessionKey . '"}';
    $commitUtcTime = gmdate('Ymd\THis\Z');
    
    $commitHeaders = [
        'X-Amz-Content-Sha256' => hash('sha256', $commitData),
        'x-amz-security-token' => $authToken['session_token'],
        'X-Amz-Date' => $commitUtcTime,
    ];
    
    $commitSigner = new VolcanoSigner($authToken['access_key'], $authToken['secret_key'], $commitUtcTime);
    $commitHeaders = $commitSigner->setRequest('POST', $commitUrl, $commitHeaders, $commitData)->addAuthorization();
    
    $formattedCommitHeaders = [];
    foreach ($commitHeaders as $key => $value) {
        $formattedCommitHeaders[] = $key . ': ' . $value;
    }
    $formattedCommitHeaders = array_merge($formattedCommitHeaders, [
        'Host: ' . $uploadHost,
        'Connection: keep-alive',
        'Content-Type: application/json',
        'User-Agent: Mozilla/5.0 (Linux; Android 15; V2338A Build/AP3A.240905.015.A2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Mobile Safari/537.36',
        'Accept: */*',
        'Origin: https://www.doubao.com',
        'Referer: https://www.doubao.com/',
    ]);
    
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $commitUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $commitData);
    curl_setopt($ch, CURLOPT_HTTPHEADER, $formattedCommitHeaders);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    
    $commitResponse = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200) {
        throw new Exception("CommitImageUpload failed: HTTP code $httpCode");
    }
    
    $commitData = json_decode($commitResponse, true);
    if (isset($commitData['Error'])) {
        throw new Exception("CommitImageUpload error: " . $commitData['Error']['Message']);
    }
    
    return $commitData['Result']['Results'][0]['Uri'];
}

// a_bogus 签名算法函数
function generateABogus($urlParams, $bodyParams, $userAgent) {
    $timestamp = time();
    $nonce = mt_rand(100000, 999999);
    
    // 构建签名字符串
    $signString = $urlParams . $bodyParams . $userAgent . $timestamp . $nonce;
    
    // 使用SHA256哈希
    $hash = hash('sha256', $signString);
    
    // Base64编码
    $base64Hash = base64_encode($hash);
    
    // URL安全编码
    $abogus = str_replace(['+', '/', '='], ['-', '_', ''], $base64Hash);
    
    return $abogus . '&timestamp=' . $timestamp . '&nonce=' . $nonce;
}

// 完整的a_bogus算法实现
function getABogus($urlParams, $bodyParams, $userAgent) {
    function get_arr($input) {
        $result = [];
        for ($i = 0; $i < strlen($input); $i++) {
            $result[] = ord($input[$i]);
        }
        return $result;
    }

    function getGarbledString($str1, $str2, $str3) {
        $combined = $str1 . $str2 . $str3;
        $timestamp = time();
        $result = '';
        
        for ($i = 0; $i < strlen($combined); $i++) {
            $charCode = ord($combined[$i]);
            $result .= chr(($charCode + $timestamp + $i) % 256);
        }
        
        return $result;
    }

    $garbledString = getGarbledString($urlParams, $bodyParams, $userAgent);
    $arr = get_arr($garbledString);
    
    $signature = '';
    foreach ($arr as $byte) {
        $signature .= dechex($byte);
    }
    
    $base64Signature = base64_encode($signature);
    
    return urlencode($base64Signature);
}

// 主流程开始
try {
    // 获取请求参数，兼容GET和POST
    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // 处理POST请求
        $rawData = file_get_contents('php://input');
        $postData = json_decode($rawData, true);
        
        $description = trim($postData['description'] ?? ($_POST['description'] ?? ''));
        $type = trim($postData['type'] ?? ($_POST['type'] ?? '二次元'));
        $ratio = trim($postData['ratio'] ?? ($_POST['ratio'] ?? '16:9'));
        $conversation_id = trim($postData['conversation_id'] ?? ($_POST['conversation_id'] ?? ''));
        $Cookie = trim($postData['Cookie'] ?? ($_POST['Cookie'] ?? ''));
        $url = trim($postData['url'] ?? ($_POST['url'] ?? ''));
    } else {
        // 处理GET请求
        $description = trim($_GET['description'] ?? '');
        $type = trim($_GET['type'] ?? '二次元');
        $ratio = trim($_GET['ratio'] ?? '16:9');
        $conversation_id = trim($_GET['conversation_id'] ?? '');
        $Cookie = trim($_GET['Cookie'] ?? '');
        $url = trim($_GET['url'] ?? '');
    }

    // 检查必要参数
    if (empty($conversation_id)) {
        echo json_encode([
            'code' => 400,
            'msg' => '没有输入豆包对话conversation_id',
            'text' => '',
            'image_url' => []
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    if (empty($Cookie)) {
        echo json_encode([
            'code' => 400,
            'msg' => '没有输入豆包Cookie',
            'text' => '',
            'image_url' => []
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 检查描述是否为空
    if (empty($description)) {
        echo json_encode([
            'code' => 400,
            'msg' => '请输入描述内容',
            'text' => '',
            'image_url' => []
        ], JSON_UNESCAPED_UNICODE);
        exit;
    }

    // 解析Cookie字符串为数组
    $cookieArray = [];
    $cookiePairs = explode(';', $Cookie);
    foreach ($cookiePairs as $pair) {
        $pair = trim($pair);
        if (empty($pair)) continue;
        $keyValue = explode('=', $pair, 2);
        if (count($keyValue) === 2) {
            $cookieArray[trim($keyValue[0])] = trim($keyValue[1]);
        }
    }

    $fileKey = '';
    $fileName = '';

    // 如果有URL参数，执行图生图流程
    if (!empty($url)) {
        try {
            // 1. 下载图片
            $imageData = downloadImage($url);
            if (strlen($imageData) === 0) {
                throw new Exception("Downloaded image is empty");
            }
            
            // 2. 上传图片到豆包
            $fileKey = uploadToDoubao($imageData, $cookieArray);
            $fileName = basename($fileKey);
            
        } catch (Exception $e) {
            echo json_encode([
                'code' => 500,
                'msg' => '图片处理失败: ' . $e->getMessage(),
                'text' => '',
                'image_url' => []
            ], JSON_UNESCAPED_UNICODE);
            exit;
        }
    }

    // 构建请求数据
    $local_message_id = generateUUIDv4();
    
    if (!empty($url)) {
        // 图生图请求参数（使用新格式）
        $data = [
            'messages' => [
                [
                    'content' => json_encode([
                        'text' => "图片风格为「{$type}」，比例 「{$ratio}」{$description}",
                        'model' => 'Seedream 4.0',
                        'template_type' => 'placeholder'
                    ]),
                    'content_type' => 2009,
                    'attachments' => [
                        [
                            'type' => 'image',
                            'key' => $fileKey,
                            'extra' => [
                                'refer_types' => 'overall'
                            ],
                            'identifier' => generateUUIDv4()
                        ]
                    ]
                ]
            ],
            'completion_option' => [
                'is_regen' => false,
                'with_suggest' => false,
                'need_create_conversation' => false,
                'launch_stage' => 1,
                'is_replace' => false,
                'is_delete' => false,
                'message_from' => 0,
                'use_auto_cot' => false,
                'resend_for_regen' => false,
                'event_id' => '0'
            ],
            'evaluate_option' => [
                'web_ab_params' => ''
            ],
            'section_id' => '22090033205535490',
            'conversation_id' => $conversation_id,
            'local_message_id' => $local_message_id
        ];
    } else {
        // 文生图请求参数
        $data = [
            'messages' => [
                [
                    'content' => json_encode([
                        'text' => "图片风格为「{$type}」，比例 「{$ratio}」{$description}"
                    ]),
                    'content_type' => 2009,
                    'attachments' => []
                ]
            ],
            'completion_option' => [
                'is_regen' => false,
                'with_suggest' => false,
                'need_create_conversation' => false,
                'launch_stage' => 1,
                'is_replace' => false,
                'is_delete' => false,
                'message_from' => 0,
                'use_auto_cot' => false,
                'event_id' => '0'
            ],
            'section_id' => '17572373948064514',
            'conversation_id' => $conversation_id,
            'local_message_id' => $local_message_id
        ];
    }

    // 生成动态的a_bogus签名
    $urlParams = 'device_platform=webapp&aid=497858&device_id=7541617037106775587&device_platform=web&language=zh&pc_version=2.32.2&pkg_type=release_version&real_aid=497858&region=CN&samantha_web=1&sys_region=CN&tea_uuid=7541617042383373878&use-olympus-account=1&version_code=20800&web_id=7541617042383373878&web_tab_id=2569b86f-1f5e-44aa-90af-ef6ba6585fa1';
    $bodyParams = json_encode($data);
    $userAgent = 'Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Mobile Safari/537.36';

    // 生成a_bogus签名
    $a_bogus = getABogus($urlParams, $bodyParams, $userAgent);

    // 构建请求URL
    $requestUrl = 'https://www.doubao.com/samantha/chat/completion?' . $urlParams . '&msToken=59Q4awwY2WeDvfOXnCZjlXTDtNc29Bb9OtvTLwLVs7pW9f944uFo_X9AhR_MXwjIMmtaImgXjlLaPePq6BLvLG21tM8B5K6oWXDYKbkzDvXwkDV1YeyJLimYOZsTLCLnn0b5bKsZtNMrDxj7JIVNqJuBKy1YpP1PWNPsNWzU72MMyPlfSCUqsIc%3D&a_bogus=' . $a_bogus;

    // 初始化cURL
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $requestUrl);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $bodyParams);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Host: www.doubao.com',
        'Connection: keep-alive',
        'x-flow-trace: 04-001c05df5e185cbb0018ef2b6f4d7205-000e2f6ebafac84a-01',
        'sec-ch-ua-platform: "Android"',
        'sec-ch-ua: "Chromium";v="136", "Google Chrome";v="136", "Not.A/Brand";v="99"',
        'sec-ch-ua-mobile: ?1',
        'Agw-Js-Conv: str, str',
        'last-event-id: undefined',
        'User-Agent: ' . $userAgent,
        'Content-Type: application/json',
        'Accept: */*',
        'Origin: https://www.doubao.com',
        'Sec-Fetch-Site: same-origin',
        'Sec-Fetch-Mode: cors',
        'Sec-Fetch-Dest: empty',
        'Referer: https://www.doubao.com/chat/13333378884003074',
        'Accept-Language: zh-CN,zh;q=0.9,sq;q=0.8',
        'Cookie: ' . $Cookie
    ]);

    // 设置cURL选项
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
    curl_setopt($ch, CURLOPT_TIMEOUT, 120); // 设置120秒超时

    // 执行请求
    $response = curl_exec($ch);

    // 检查是否有错误发生
    if (curl_errno($ch)) {
        echo json_encode([
            'code' => 500,
            'msg' => '请求失败: ' . curl_error($ch),
            'text' => '',
            'image_url' => []
        ], JSON_UNESCAPED_UNICODE);
        curl_close($ch);
        exit;
    }

    // 关闭cURL资源
    curl_close($ch);

    // 处理响应
    $responseLines = explode("\n", $response);
    $imageUrls = [];
    $text = '';
    $success = false;

    foreach ($responseLines as $line) {
        if (strpos($line, 'data: ') === 0) {
            $jsonStr = substr($line, 6);
            $data = json_decode($jsonStr, true);
            
            if (isset($data['event_data'])) {
                $eventData = json_decode($data['event_data'], true);
                
                // 提取文本描述
                if (isset($eventData['message']['content_type']) && $eventData['message']['content_type'] == 10000) {
                    $content = json_decode($eventData['message']['content'], true);
                    if (isset($content['text']) && !empty($content['text'])) {
                        $text .= $content['text'];
                    }
                }
                
                // 提取图片URL
                if (isset($eventData['message']['content_type']) && $eventData['message']['content_type'] == 2074) {
                    $content = json_decode($eventData['message']['content'], true);
                    if (isset($content['creations']) && is_array($content['creations'])) {
                        foreach ($content['creations'] as $creation) {
                            if (isset($creation['type']) && $creation['type'] == 1 && 
                                isset($creation['image']['image_ori_raw']['url'])) {
                                // 处理Unicode编码并去除斜杠
                                $url = stripslashes($creation['image']['image_ori_raw']['url']);
                                $imageUrls[] = $url;
                            }
                        }
                        $success = true;
                    }
                }
            }
        }
    }

    // 构建最终响应
    $result = [
        'code' => $success ? 200 : 500,
        'msg' => "图片风格为「{$type}」，比例 「{$ratio}」{$description}",
        'text' => $text,
        'image_url' => $imageUrls
    ];

    // 如果是图生图，添加上传的图片信息
    if (!empty($url)) {
        $result['uploaded_image'] = [
            'file_key' => $fileKey,
            'file_name' => $fileName
        ];
    }

    // 输出JSON响应
    echo json_encode($result, JSON_UNESCAPED_UNICODE);

} catch (Exception $e) {
    echo json_encode([
        'code' => 500,
        'msg' => '系统错误: ' . $e->getMessage(),
        'text' => '',
        'image_url' => []
    ], JSON_UNESCAPED_UNICODE);
}
