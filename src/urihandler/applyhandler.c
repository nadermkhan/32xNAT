#include "handler.h"
#include "timer.h"
#include "helper.h"

#include <sys/param.h>
#include <timer.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "nvs.h"
#include "cmd_nvs.h"
#include "router_globals.h"
#include "esp_wifi.h"
#include "esp_log.h"

static const char *TAG = "ApplyHandler";

// Forward declarations
size_t url_decode(const char* src, char* dest, size_t dest_size);
bool is_valid_utf8(const char* str);
esp_err_t validate_and_process_ssid(const char* raw_ssid, char* processed_ssid, size_t max_len);

// URL decoding function for UTF-8 support
size_t url_decode(const char* src, char* dest, size_t dest_size) {
    if (!src || !dest || dest_size == 0) {
        return 0;
    }
    
    size_t src_len = strlen(src);
    size_t dest_idx = 0;
    
    for (size_t i = 0; i < src_len && dest_idx < dest_size - 1; i++) {
        if (src[i] == '%' && i + 2 < src_len) {
            // Decode hex-encoded character
            char hex[3] = {src[i+1], src[i+2], '\0'};
            char* endptr;
            long val = strtol(hex, &endptr, 16);
            if (*endptr == '\0' && val >= 0 && val <= 255) {
                dest[dest_idx++] = (char)val;
                i += 2; // Skip the hex digits
            } else {
                dest[dest_idx++] = src[i]; // Keep original if invalid hex
            }
        } else if (src[i] == '+') {
            dest[dest_idx++] = ' '; // Convert + to space
        } else {
            dest[dest_idx++] = src[i];
        }
    }
    
    dest[dest_idx] = '\0';
    return dest_idx;
}

// UTF-8 validation function
bool is_valid_utf8(const char* str) {
    if (!str) return false;
    
    const unsigned char* bytes = (const unsigned char*)str;
    while (*bytes) {
        if ((*bytes & 0x80) == 0) {
            // ASCII character
            bytes++;
        } else if ((*bytes & 0xE0) == 0xC0) {
            // 2-byte sequence
            if ((bytes[1] & 0xC0) != 0x80) return false;
            bytes += 2;
        } else if ((*bytes & 0xF0) == 0xE0) {
            // 3-byte sequence
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80) return false;
            bytes += 3;
        } else if ((*bytes & 0xF8) == 0xF0) {
            // 4-byte sequence
            if ((bytes[1] & 0xC0) != 0x80 || (bytes[2] & 0xC0) != 0x80 || (bytes[3] & 0xC0) != 0x80) return false;
            bytes += 4;
        } else {
            return false; // Invalid UTF-8
        }
    }
    return true;
}

// UTF-8 safe SSID validation and processing
esp_err_t validate_and_process_ssid(const char* raw_ssid, char* processed_ssid, size_t max_len) {
    if (!raw_ssid || !processed_ssid || max_len == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    
    // First, URL decode the SSID to handle UTF-8 characters properly
    size_t decoded_len = url_decode(raw_ssid, processed_ssid, max_len - 1);
    if (decoded_len == 0) {
        ESP_LOGE(TAG, "Failed to decode SSID");
        return ESP_ERR_INVALID_ARG;
    }
    
    // Validate UTF-8
    if (!is_valid_utf8(processed_ssid)) {
        ESP_LOGE(TAG, "SSID contains invalid UTF-8 sequences");
        return ESP_ERR_INVALID_ARG;
    }
    
    // Check WiFi SSID length limits (32 bytes max)
    if (strlen(processed_ssid) > 32) {
        ESP_LOGW(TAG, "SSID too long (%d bytes), truncating to 32 bytes", strlen(processed_ssid));
        // Find safe UTF-8 truncation point
        size_t safe_len = 32;
        while (safe_len > 0 && (processed_ssid[safe_len] & 0x80) && !(processed_ssid[safe_len] & 0x40)) {
            safe_len--;
        }
        processed_ssid[safe_len] = '\0';
    }
    
    return ESP_OK;
}

void setApByQuery(char *urlContent, nvs_handle_t nvs)
{
    size_t contentLength = 600;
    char param[contentLength];
    char processed_ssid[64]; // Larger buffer for processing
    
    // Handle AP SSID with UTF-8 support
    readUrlParameterIntoBuffer(urlContent, "ap_ssid", param, contentLength);
    if (strlen(param) > 0) {
        if (validate_and_process_ssid(param, processed_ssid, sizeof(processed_ssid)) == ESP_OK) {
            ESP_LOGI(TAG, "Setting AP SSID to: %s", processed_ssid);
            ESP_ERROR_CHECK(nvs_set_str(nvs, "ap_ssid", processed_ssid));
        } else {
            ESP_LOGE(TAG, "Invalid AP SSID, keeping current setting");
        }
    }
    
    // Handle AP password with URL decoding
    readUrlParameterIntoBuffer(urlContent, "ap_password", param, contentLength);
    if (strlen(param) > 0) {
        char decoded_password[256];
        size_t pwd_len = url_decode(param, decoded_password, sizeof(decoded_password));
        
        if (strlen(decoded_password) < 8) {
            nvs_erase_key(nvs, "ap_passwd");
        } else {
            ESP_ERROR_CHECK(nvs_set_str(nvs, "ap_passwd", decoded_password));
        }
    }

    readUrlParameterIntoBuffer(urlContent, "ssid_hidden", param, contentLength);
    if (strcmp(param, "on") == 0) {
        ESP_LOGI(TAG, "AP-SSID should be hidden.");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "ssid_hidden", 1));
    } else {
        nvs_erase_key(nvs, "ssid_hidden");
    }
}

void setStaByQuery(char *urlContent, nvs_handle_t nvs)
{
    size_t contentLength = 600;
    char param[contentLength];
    char processed_ssid[64];
    
    // Handle STA SSID with UTF-8 support
    readUrlParameterIntoBuffer(urlContent, "ssid", param, contentLength);
    if (strlen(param) > 0) {
        if (validate_and_process_ssid(param, processed_ssid, sizeof(processed_ssid)) == ESP_OK) {
            ESP_LOGI(TAG, "Setting STA SSID to: %s", processed_ssid);
            ESP_ERROR_CHECK(nvs_set_str(nvs, "ssid", processed_ssid));
        } else {
            ESP_LOGE(TAG, "Invalid STA SSID, keeping current setting");
        }
    }
    
    // Handle STA password with URL decoding
    readUrlParameterIntoBuffer(urlContent, "password", param, contentLength);
    if (strlen(param) > 0) {
        char decoded_password[256];
        size_t pwd_len = url_decode(param, decoded_password, sizeof(decoded_password));
        ESP_ERROR_CHECK(nvs_set_str(nvs, "passwd", decoded_password));
    }
}

void setWpa2(char *urlContent, nvs_handle_t nvs)
{
    size_t contentLength = strlen(urlContent);
    char param[contentLength];
    readUrlParameterIntoBuffer(urlContent, "sta_identity", param, contentLength);
    if (strlen(param) > 0)
    {
        ESP_LOGI(TAG, "WPA2 Identity set to '%s'", param);
        ESP_ERROR_CHECK(nvs_set_str(nvs, "sta_identity", param));
    }
    else
    {
        ESP_LOGI(TAG, "WPA2 Identity will be deleted");
        nvs_erase_key(nvs, "sta_identity");
    }

    readUrlParameterIntoBuffer(urlContent, "sta_user", param, contentLength);

    if (strlen(param) > 0)
    {
        ESP_LOGI(TAG, "WPA2 user set to '%s'", param);
        ESP_ERROR_CHECK(nvs_set_str(nvs, "sta_user", param));
    }
    else
    {
        ESP_LOGI(TAG, "WPA2 user will be deleted");
        nvs_erase_key(nvs, "sta_user");
    }
    readUrlParameterIntoBuffer(urlContent, "cer", param, contentLength);

    if (strlen(param) > 0)
    {
        nvs_erase_key(nvs, "cer"); // do not double size in nvs
        ESP_LOGI(TAG, "Certificate with size %d set", strlen(param));
        ESP_ERROR_CHECK(nvs_set_blob(nvs, "cer", param, contentLength));
    }
    else
    {
        ESP_LOGI(TAG, "Certificate will be deleted");
        nvs_erase_key(nvs, "cer");
    }
}

void applyApStaConfig(char *buf)
{
    nvs_handle_t nvs;
    ESP_ERROR_CHECK(nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs));
    setApByQuery(buf, nvs);
    setStaByQuery(buf, nvs);
    setWpa2(buf, nvs);
    ESP_ERROR_CHECK(nvs_commit(nvs));
    nvs_close(nvs);
}

void eraseNvs()
{
    ESP_LOGW(TAG, "Erasing %s", PARAM_NAMESPACE);
    int argc = 2;
    char *argv[argc];
    argv[0] = "erase_namespace";
    argv[1] = PARAM_NAMESPACE;
    erase_ns(argc, argv);
}

void setDNSToDefault(nvs_handle_t *nvs)
{
    nvs_erase_key(*nvs, "custom_dns");
    ESP_LOGI(TAG, "DNS set to default (uplink network)");
}

void setMACToDefault(nvs_handle_t *nvs)
{
    nvs_erase_key(*nvs, "custom_mac");
    ESP_LOGI(TAG, "MAC set to default");
}

bool str2mac(const char *mac)
{
    uint8_t values[6] = {0};
    if (6 == sscanf(mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]))
    {
        return true;
    }
    else
    {
        return false;
    }
}

char *getRedirectUrl(httpd_req_t *req)
{

    size_t buf_len = 16;
    char *host = malloc(buf_len);
    httpd_req_get_hdr_value_str(req, "Host", host, buf_len);
    ESP_LOGI(TAG, "Host of request is '%s'", host);
    char *str = malloc(strlen("http://") + buf_len);
    strcpy(str, "http://");
    if (strcmp(host, DEFAULT_AP_IP_CLASS_A) == 0 || strcmp(host, DEFAULT_AP_IP_CLASS_B) == 0 || strcmp(host, DEFAULT_AP_IP_CLASS_C) == 0)
    {
        char *defaultIP = getDefaultIPByNetmask();
        strcat(str, defaultIP);
        free(defaultIP);
    }
    else
    {
        strcat(str, host);
    }
    free(host);

    return str;
}

void applyAdvancedConfig(char *buf)
{
    ESP_LOGI(TAG, "Applying advanced config");
    nvs_handle_t nvs;
    nvs_open(PARAM_NAMESPACE, NVS_READWRITE, &nvs);

    size_t contentLength = 250;
    char param[contentLength];
    readUrlParameterIntoBuffer(buf, "keepalive", param, contentLength);

    if (strlen(param) > 0)
    {
        ESP_LOGI(TAG, "keep alive will be enabled");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "keep_alive", 1));
    }
    else
    {
        ESP_LOGI(TAG, "keep alive will be disabled");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "keep_alive", 0));
    }

    readUrlParameterIntoBuffer(buf, "ledenabled", param, contentLength);
    if (strlen(param) > 0)
    {
        ESP_LOGI(TAG, "ON Board LED will be enabled");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "led_disabled", 0));
    }
    else
    {
        ESP_LOGI(TAG, "ON Board LED will be disabled");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "led_disabled", 1));
    }

    readUrlParameterIntoBuffer(buf, "natenabled", param, contentLength);
    if (strlen(param) > 0)
    {
        ESP_LOGI(TAG, "NAT will be enabled");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "nat_disabled", 0));
    }
    else
    {
        ESP_LOGI(TAG, "NAT will be disabled");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "nat_disabled", 1));
    }

    readUrlParameterIntoBuffer(buf, "wsenabled", param, contentLength);
    if (strlen(param) == 0)
    {
        ESP_LOGI(TAG, "Webserver will be disabled");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "lock", 1));
    }

    readUrlParameterIntoBuffer(buf, "custommac", param, contentLength);
    if (strlen(param) > 0)
    {
        char macaddress[contentLength];
        readUrlParameterIntoBuffer(buf, "macaddress", macaddress, contentLength);
        if (strcmp("random", param) == 0)
        {
            ESP_LOGI(TAG, "MAC address set to random");
                        ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_mac", param));
        }
        else if (strlen(macaddress) > 0)
        {
            int success = str2mac(macaddress);
            if (success)
            {
                ESP_LOGI(TAG, "MAC address set to: %s", macaddress);
                ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_mac", macaddress));
            }
            else
            {
                ESP_LOGI(TAG, "MAC address '%s' is invalid", macaddress);
                setMACToDefault(&nvs);
            }
        }
        else
        {
            setMACToDefault(&nvs);
        }
    }
    readUrlParameterIntoBuffer(buf, "dns", param, contentLength);
    if (strlen(param) > 0)
    {
        if (strcmp(param, "custom") == 0)
        {
            char customDnsParam[contentLength];
            readUrlParameterIntoBuffer(buf, "dnsip", customDnsParam, contentLength);
            if (strlen(customDnsParam) > 0)
            {
                uint32_t ipasInt = esp_ip4addr_aton(customDnsParam);
                if (ipasInt == UINT32_MAX || ipasInt == 0)
                {
                    ESP_LOGW(TAG, "Invalid custom DNS. Setting back to default!");
                    setDNSToDefault(&nvs);
                }
                else
                {
                    esp_ip4_addr_t *addr = malloc(16);
                    addr->addr = ipasInt;
                    esp_ip4addr_ntoa(addr, customDnsParam, 16);
                    ESP_LOGI(TAG, "DNS set to: %s", customDnsParam);
                    ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_dns", customDnsParam));
                    free(addr);
                }
            }
            else
            {
                setDNSToDefault(&nvs);
            }
        }
        else
        {
            ESP_LOGI(TAG, "DNS set to: %s", param);
            ESP_ERROR_CHECK(nvs_set_str(nvs, "custom_dns", param));
        }
    }
    else
    {
        setDNSToDefault(&nvs);
    }
    readUrlParameterIntoBuffer(buf, "netmask", param, contentLength);
    if (strlen(param) > 0)
    {
        if (strcmp("classa", param) == 0)
        {
            ESP_LOGI(TAG, "Netmask set to Class A");
            ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_A));
        }
        else if (strcmp("classb", param) == 0)
        {
            ESP_LOGI(TAG, "Netmask set to Class B");
            ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_B));
        }
        else if (strcmp("classc", param) == 0)
        {
            ESP_LOGI(TAG, "Netmask set to Class C");
            ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_C));
        }
        else
        {
            readUrlParameterIntoBuffer(buf, "mask", param, contentLength);
            if (is_valid_subnet_mask(param))
            {
                ESP_LOGI(TAG, "Netmask set to %s", param);
                ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", param));
            }
            else
            {
                ESP_LOGW(TAG, "Invalid custom subnetmask. Setting to default.");
                ESP_ERROR_CHECK(nvs_set_str(nvs, "netmask", DEFAULT_NETMASK_CLASS_C));
            }
        }
    }
    
    // Handle hostname with URL decoding
    readUrlParameterIntoBuffer(buf, "hostname", param, contentLength);
    if (strlen(param) > 0)
    {
        char decoded_hostname[64];
        url_decode(param, decoded_hostname, sizeof(decoded_hostname));
        ESP_LOGI(TAG, "Set hostname to: %s", decoded_hostname);
        ESP_ERROR_CHECK(nvs_set_str(nvs, "hostname", decoded_hostname));
    }
    else
    {
        ESP_LOGI(TAG, "Erasing hostname. Will be regenerated on boot.");
        nvs_erase_key(nvs, "hostname");
    }

    readUrlParameterIntoBuffer(buf, "octet", param, contentLength);
    int octet = atoi(param);
    if (strlen(param) > 0 && octet >= 0 && octet <= 255)
    {
        ESP_LOGI(TAG, "Set third octet to: %d", octet);
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "octet", octet));
    }
    else
    {
        ESP_LOGW(TAG, "Invalid octet parameter. Will be erased");
        nvs_erase_key(nvs, "octet");
    }
    readUrlParameterIntoBuffer(buf, "txpower", param, contentLength);
    int txPower = atoi(param);
    if (txPower >= 8 && txPower <= 84)
    {
        ESP_LOGI(TAG, "Setting Wifi tx power to %d.", txPower);
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "txpower", txPower));
    }
    readUrlParameterIntoBuffer(buf, "bandwith", param, contentLength);
    int useLowerBandwith = atoi(param);
    if (useLowerBandwith == 1)
    {
        ESP_LOGI(TAG, "Using lower bandwith with 40 MHz");
        ESP_ERROR_CHECK(nvs_set_i32(nvs, "lower_bandwith", 1));
    }
    else
    {
        nvs_erase_key(nvs, "lower_bandwith");
    }

    nvs_commit(nvs);
    nvs_close(nvs);
}

esp_err_t apply_get_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return redirectToLock(req);
    }
    extern const char apply_start[] asm("_binary_apply_html_start");
    extern const char apply_end[] asm("_binary_apply_html_end");
    ESP_LOGI(TAG, "Requesting apply page");
    closeHeader(req);

    char *redirectUrl = getRedirectUrl(req);
    char *apply_page = malloc(apply_end - apply_start + strlen(redirectUrl) - 2);

    ESP_LOGI(TAG, "Redirecting after apply to '%s'", redirectUrl);
    sprintf(apply_page, apply_start, redirectUrl);
    free(redirectUrl);

    return httpd_resp_send(req, apply_page, HTTPD_RESP_USE_STRLEN);
}

esp_err_t apply_post_handler(httpd_req_t *req)
{
    if (isLocked())
    {
        return redirectToLock(req);
    }
    httpd_req_to_sockfd(req);

    int remaining = req->content_len;
    int ret = 0;
    int bufferLength = req->content_len;
    ESP_LOGI(TAG, "Content length  => %d", req->content_len);
    char buf[100]; // 100 byte chunk
    char content[bufferLength];
    strcpy(content, ""); // Fill initial

    while (remaining > 0)
    {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf, MIN(remaining, sizeof(buf)))) <= 0)
        {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT)
            {
                continue;
            }
            ESP_LOGE(TAG, "Timeout occured %d", ret);
            return ESP_FAIL;
        }
        buf[ret] = '\0'; // add NUL terminator
        strcat(content, buf);
        remaining -= ret;
        ESP_LOGI(TAG, "%d bytes total received -> %d left", strlen(content), remaining);
    }
    char funcParam[9];

    ESP_LOGI(TAG, "getting content %s", content);

    readUrlParameterIntoBuffer(content, "func", funcParam, 9);

    ESP_LOGI(TAG, "Function => %s", funcParam);

    if (strcmp(funcParam, "config") == 0)
    {
        ESP_LOGI(TAG, "Applying WiFi configuration with UTF-8 support");
        applyApStaConfig(content);
    }
    if (strcmp(funcParam, "erase") == 0)
    {
        eraseNvs();
    }
    if (strcmp(funcParam, "advanced") == 0)
    {
        applyAdvancedConfig(content);
    }
    restartByTimerinS(1);

    return apply_get_handler(req);
}