<?php
// Устанавливаем заголовки для CORS и JSON-ответа
header("Access-Control-Allow-Origin: *");
header("Content-Type: application/json; charset=UTF-8");

// --- HELPER FUNCTIONS ---

/**
 * Получает расширенные данные о геолокации по IP-адресу.
 * @param string|null $ip IP-адрес.
 * @return array Ассоциативный массив с геолокацией.
 */
function get_geolocation($ip) {
    $result = ['location' => null, 'isp' => null, 'timezone' => null];
    if (empty($ip) || !filter_var($ip, FILTER_VALIDATE_IP)) {
        return $result;
    }
    
    $geo_url = "http://ip-api.com/json/{$ip}?fields=status,message,country,countryCode,city,isp,timezone";
    $geo_ch = curl_init($geo_url);
    curl_setopt($geo_ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($geo_ch, CURLOPT_TIMEOUT, 3);
    $geo_response = curl_exec($geo_ch);
    curl_close($geo_ch);

    if ($geo_response) {
        $geo_data = json_decode($geo_response, true);
        if (isset($geo_data['status']) && $geo_data['status'] === 'success') {
            $location_string = get_flag_emoji($geo_data['countryCode']) . " " . $geo_data['country'];
            if (!empty($geo_data['city'])) {
                $location_string .= ", " . $geo_data['city'];
            }
            $result['location'] = $location_string;
            $result['isp'] = $geo_data['isp'] ?? null;
            $result['timezone'] = $geo_data['timezone'] ?? null;
        }
    }
    return $result;
}

/**
 * Преобразует двухбуквенный код страны в эмодзи флага.
 * @param string $countryCode Код страны.
 * @return string Эмодзи флага.
 */
function get_flag_emoji($countryCode) {
    if (strlen($countryCode) !== 2) return '';
    $regionalOffset = 0x1F1A5;
    return mb_convert_encoding('&#' . ($regionalOffset + ord($countryCode[0])) . ';', 'UTF-8', 'HTML-ENTITIES')
         . mb_convert_encoding('&#' . ($regionalOffset + ord($countryCode[1])) . ';', 'UTF-8', 'HTML-ENTITIES');
}

/**
 * Получает информацию об SSL-сертификате.
 * @param string $hostname Имя хоста.
 * @return array|null Информация о сертификате или null в случае ошибки.
 */
function get_ssl_info($hostname) {
    try {
        $streamContext = stream_context_create(["ssl" => ["capture_peer_cert" => true]]);
        $client = @stream_socket_client("ssl://{$hostname}:443", $errno, $errstr, 5, STREAM_CLIENT_CONNECT, $streamContext);
        if (!$client) return null;

        $params = stream_context_get_params($client);
        $cert = openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        fclose($client);

        if (!$cert) return null;

        $validTo = date(DateTime::ATOM, $cert['validTo_time_t']);
        $daysLeft = (int)floor(($cert['validTo_time_t'] - time()) / (60 * 60 * 24));

        return [
            'issuer' => $cert['issuer']['CN'] ?? $cert['issuer']['O'] ?? 'N/A',
            'expires_at' => $validTo,
            'days_left' => $daysLeft > 0 ? $daysLeft : 0,
        ];
    } catch (Exception $e) {
        return null;
    }
}

/**
 * Парсит сырые HTTP-заголовки в ассоциативный массив.
 * @param string $header_string Строка с заголовками.
 * @return array Массив заголовков.
 */
function parse_headers($header_string) {
    $headers = [];
    $lines = explode("\r\n", $header_string);
    foreach ($lines as $line) {
        if (strpos($line, ':') !== false) {
            list($key, $value) = explode(':', $line, 2);
            $headers[trim($key)] = trim($value);
        }
    }
    return $headers;
}

/**
 * Получает DNS-записи для домена.
 * @param string $hostname Имя хоста.
 * @return array DNS-записи.
 */
function get_dns_records($hostname) {
    $records = [];
    $types = [DNS_A, DNS_AAAA, DNS_MX, DNS_NS, DNS_TXT];
    foreach ($types as $type) {
        $dns = @dns_get_record($hostname, $type);
        if ($dns) {
            $records[dns_type_to_string($type)] = $dns;
        }
    }
    return $records;
}

/**
 * Конвертирует тип DNS в строку.
 */
function dns_type_to_string($type) {
    $map = [DNS_A => 'A', DNS_AAAA => 'AAAA', DNS_MX => 'MX', DNS_NS => 'NS', DNS_TXT => 'TXT'];
    return $map[$type] ?? 'UNKNOWN';
}

/**
 * Определяет технологический стек на основе заголовков.
 * @param array $headers HTTP-заголовки.
 * @return array Обнаруженные технологии.
 */
function detect_tech_stack($headers) {
    $tech = [];
    // Проверка веб-сервера
    if (isset($headers['Server'])) {
        $server = strtolower($headers['Server']);
        if (strpos($server, 'nginx') !== false) $tech[] = 'Nginx';
        if (strpos($server, 'apache') !== false) $tech[] = 'Apache';
        if (strpos($server, 'litespeed') !== false) $tech[] = 'LiteSpeed';
        if (strpos($server, 'iis') !== false) $tech[] = 'Microsoft-IIS';
    }
    // Проверка языка/фреймворка
    if (isset($headers['X-Powered-By'])) {
        $poweredBy = strtolower($headers['X-Powered-By']);
        if (strpos($poweredBy, 'php') !== false) $tech[] = 'PHP';
        if (strpos($poweredBy, 'asp.net') !== false) $tech[] = 'ASP.NET';
    }
    // Проверка CMS
    if (isset($headers['Link']) && strpos($headers['Link'], 'wp.me') !== false) {
        $tech[] = 'WordPress';
    }
    if (isset($headers['X-Drupal-Cache'])) {
        $tech[] = 'Drupal';
    }
    return array_unique($tech);
}


// --- MAIN LOGIC ---

$url = isset($_GET['url']) ? trim($_GET['url']) : '';

if (empty($url) || !filter_var($url, FILTER_VALIDATE_URL)) {
    http_response_code(400);
    echo json_encode(['status' => 'Ошибка', 'message' => 'Некорректный или пустой URL.', 'http_code' => 400]);
    exit;
}

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HEADER, true);
curl_setopt($ch, CURLOPT_TIMEOUT, 15);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_USERAGENT, 'DevPulse-Checker/1.4-Ultimate');

$response_content = curl_exec($ch);

if (curl_errno($ch)) {
    http_response_code(500);
    echo json_encode(['status' => 'Ошибка', 'message' => 'Не удалось подключиться: ' . curl_error($ch), 'http_code' => 0]);
    curl_close($ch);
    exit;
}

$header_size = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
$header_string = substr($response_content, 0, $header_size);
$headers = parse_headers($header_string);

$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
$ip = curl_getinfo($ch, CURLINFO_PRIMARY_IP);
$geo_info = get_geolocation($ip);
$parsed_url = parse_url(curl_getinfo($ch, CURLINFO_EFFECTIVE_URL));
$hostname = $parsed_url['host'];
$ssl_info = ($parsed_url['scheme'] === 'https') ? get_ssl_info($hostname) : null;
$dns_records = get_dns_records($hostname);
$tech_stack = detect_tech_stack($headers);

$response = [
    'url' => curl_getinfo($ch, CURLINFO_EFFECTIVE_URL),
    'status' => ($httpCode >= 200 && $httpCode < 400) ? 'Работает' : 'Ошибка',
    'http_code' => $httpCode,
    'server' => [
        'ip' => $ip,
        'location' => $geo_info['location'],
        'timezone' => $geo_info['timezone'],
        'isp' => $geo_info['isp']
    ],
    'timing' => [
        'total' => round(curl_getinfo($ch, CURLINFO_TOTAL_TIME) * 1000),
        'dns_lookup' => round(curl_getinfo($ch, CURLINFO_NAMELOOKUP_TIME) * 1000),
        'tcp_connect' => round(curl_getinfo($ch, CURLINFO_CONNECT_TIME) * 1000),
        'ssl_handshake' => round(curl_getinfo($ch, CURLINFO_APPCONNECT_TIME) * 1000),
        'ttfb' => round(curl_getinfo($ch, CURLINFO_STARTTRANSFER_TIME) * 1000)
    ],
    'response' => [
        'content_type' => curl_getinfo($ch, CURLINFO_CONTENT_TYPE),
        'size_bytes' => curl_getinfo($ch, CURLINFO_SIZE_DOWNLOAD),
        'redirect_count' => curl_getinfo($ch, CURLINFO_REDIRECT_COUNT),
        'headers' => $headers
    ],
    'ssl' => $ssl_info,
    'dns' => $dns_records,
    'tech_stack' => $tech_stack
];

curl_close($ch);

http_response_code(200);
echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
?>
