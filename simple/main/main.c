/* Simple HTTP Server Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/

#include <string.h>
#include <stdlib.h>
#include <unistd.h>

//#include "freertos/FreeRTOS.h"
//#include "freertos/task.h"
#include "esp_log.h"
#include "driver/mcpwm_prelude.h"

#include <nvs_flash.h>
#include <sys/param.h>
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "protocol_examples_utils.h"
#include "esp_tls_crypto.h"
#include <esp_http_server.h>
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_tls.h"

#include "driver/spi_master.h"
#include "driver/gpio.h"


#if !CONFIG_IDF_TARGET_LINUX
#include <esp_wifi.h>
#include <esp_system.h>
#include "nvs_flash.h"
#include "esp_eth.h"
#endif  // !CONFIG_IDF_TARGET_LINUX

#define EXAMPLE_HTTP_QUERY_KEY_MAX_LEN  (64)

/* A simple example that demonstrates how to create GET and POST
 * handlers for the web server.
 */

static const char *TAG = "example";

float temperature_1 = 0.0;
float temperature_2 = 0.0;
float temperature_3 = 0.0;

int pwm1 = 0;
int pwm2 = 0;
int pwm3 = 0;

//mcpwm
// Please consult the datasheet of your servo before changing the following parameters
#define SERVO_MIN_PULSEWIDTH_US 500  // Minimum pulse width in microsecond
#define SERVO_MAX_PULSEWIDTH_US 4000  // Maximum pulse width in microsecond
#define SERVO_MIN_DEGREE        -90   // Minimum angle
#define SERVO_MAX_DEGREE        90    // Maximum angle

#define SERVO_PULSE_GPIO             1        // GPIO connects to the PWM signal line
#define SERVO_PULSE_GPIO_2             2        // GPIO connects to the PWM signal line
#define SERVO_TIMEBASE_RESOLUTION_HZ 1000000  // 1MHz, 1us per tick
#define SERVO_TIMEBASE_PERIOD        20000    // 20000 ticks, 20ms

int angle = 0;
int step = 2;
mcpwm_cmpr_handle_t comparator = NULL;
static mcpwm_comparator_config_t comparator_config = {
    .flags.update_cmp_on_tez = true,
};
static mcpwm_timer_handle_t timer = NULL;
static mcpwm_timer_config_t timer_config = {
    .group_id = 0,
    .clk_src = MCPWM_TIMER_CLK_SRC_DEFAULT,
    .resolution_hz = SERVO_TIMEBASE_RESOLUTION_HZ,
    .period_ticks = SERVO_TIMEBASE_PERIOD,
    .count_mode = MCPWM_TIMER_COUNT_MODE_UP,
};
static mcpwm_oper_handle_t oper = NULL;
static mcpwm_operator_config_t operator_config = {
    .group_id = 0, // operator must be in the same group to the timer
};
static mcpwm_gen_handle_t generator = NULL;
static mcpwm_generator_config_t generator_config = {
    .gen_gpio_num = SERVO_PULSE_GPIO,
};



static inline uint32_t example_angle_to_compare(int angle)
{
    return (angle - SERVO_MIN_DEGREE) * (SERVO_MAX_PULSEWIDTH_US - SERVO_MIN_PULSEWIDTH_US) / (SERVO_MAX_DEGREE - SERVO_MIN_DEGREE) + SERVO_MIN_PULSEWIDTH_US;
}



#if CONFIG_EXAMPLE_BASIC_AUTH

typedef struct {
    char    *username;
    char    *password;
} basic_auth_info_t;

#define HTTPD_401      "401 UNAUTHORIZED"           /*!< HTTP Response 401 */

static char *http_auth_basic(const char *username, const char *password)
{
    size_t out;
    char *user_info = NULL;
    char *digest = NULL;
    size_t n = 0;
    int rc = asprintf(&user_info, "%s:%s", username, password);
    if (rc < 0) {
        ESP_LOGE(TAG, "asprintf() returned: %d", rc);
        return NULL;
    }

    if (!user_info) {
        ESP_LOGE(TAG, "No enough memory for user information");
        return NULL;
    }
    esp_crypto_base64_encode(NULL, 0, &n, (const unsigned char *)user_info, strlen(user_info));

    /* 6: The length of the "Basic " string
     * n: Number of bytes for a base64 encode format
     * 1: Number of bytes for a reserved which be used to fill zero
    */
    digest = calloc(1, 6 + n + 1);
    if (digest) {
        strcpy(digest, "Basic ");
        esp_crypto_base64_encode((unsigned char *)digest + 6, n, &out, (const unsigned char *)user_info, strlen(user_info));
    }
    free(user_info);
    return digest;
}

/* An HTTP GET handler */
static esp_err_t basic_auth_get_handler(httpd_req_t *req)
{
    char *buf = NULL;
    size_t buf_len = 0;
    basic_auth_info_t *basic_auth_info = req->user_ctx;

    buf_len = httpd_req_get_hdr_value_len(req, "Authorization") + 1;
    if (buf_len > 1) {
        buf = calloc(1, buf_len);
        if (!buf) {
            ESP_LOGE(TAG, "No enough memory for basic authorization");
            return ESP_ERR_NO_MEM;
        }

        if (httpd_req_get_hdr_value_str(req, "Authorization", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Authorization: %s", buf);
        } else {
            ESP_LOGE(TAG, "No auth value received");
        }

        char *auth_credentials = http_auth_basic(basic_auth_info->username, basic_auth_info->password);
        if (!auth_credentials) {
            ESP_LOGE(TAG, "No enough memory for basic authorization credentials");
            free(buf);
            return ESP_ERR_NO_MEM;
        }

        if (strncmp(auth_credentials, buf, buf_len)) {
            ESP_LOGE(TAG, "Not authenticated");
            httpd_resp_set_status(req, HTTPD_401);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
            httpd_resp_send(req, NULL, 0);
        } else {
            ESP_LOGI(TAG, "Authenticated!");
            char *basic_auth_resp = NULL;
            httpd_resp_set_status(req, HTTPD_200);
            httpd_resp_set_type(req, "application/json");
            httpd_resp_set_hdr(req, "Connection", "keep-alive");
            int rc = asprintf(&basic_auth_resp, "{\"authenticated\": true,\"user\": \"%s\"}", basic_auth_info->username);
            if (rc < 0) {
                ESP_LOGE(TAG, "asprintf() returned: %d", rc);
                free(auth_credentials);
                return ESP_FAIL;
            }
            if (!basic_auth_resp) {
                ESP_LOGE(TAG, "No enough memory for basic authorization response");
                free(auth_credentials);
                free(buf);
                return ESP_ERR_NO_MEM;
            }
            httpd_resp_send(req, basic_auth_resp, strlen(basic_auth_resp));
            free(basic_auth_resp);
        }
        free(auth_credentials);
        free(buf);
    } else {
        ESP_LOGE(TAG, "No auth header received");
        httpd_resp_set_status(req, HTTPD_401);
        httpd_resp_set_type(req, "application/json");
        httpd_resp_set_hdr(req, "Connection", "keep-alive");
        httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"Hello\"");
        httpd_resp_send(req, NULL, 0);
    }

    return ESP_OK;
}

static httpd_uri_t basic_auth = {
    .uri       = "/basic_auth",
    .method    = HTTP_GET,
    .handler   = basic_auth_get_handler,
};

static void httpd_register_basic_auth(httpd_handle_t server)
{
    basic_auth_info_t *basic_auth_info = calloc(1, sizeof(basic_auth_info_t));
    if (basic_auth_info) {
        basic_auth_info->username = CONFIG_EXAMPLE_BASIC_AUTH_USERNAME;
        basic_auth_info->password = CONFIG_EXAMPLE_BASIC_AUTH_PASSWORD;

        basic_auth.user_ctx = basic_auth_info;
        httpd_register_uri_handler(server, &basic_auth);
    }
}
#endif


void update_http_response(float tmp1, float tmp2, float tmp3, int pwm1, int pwm2, int pwm3);

/* An HTTP GET handler */
static esp_err_t hello_get_handler(httpd_req_t *req)
{
    char*  buf;
    size_t buf_len;

    /* Get header value string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_hdr_value_len(req, "Host") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        /* Copy null terminated value string into buffer */
        if (httpd_req_get_hdr_value_str(req, "Host", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Host: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-2") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-2", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-2: %s", buf);
        }
        free(buf);
    }

    buf_len = httpd_req_get_hdr_value_len(req, "Test-Header-1") + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (httpd_req_get_hdr_value_str(req, "Test-Header-1", buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found header => Test-Header-1: %s", buf);
        }
        free(buf);
    }

    /* Read URL query string length and allocate memory for length + 1,
     * extra byte for null termination */
    buf_len = httpd_req_get_url_query_len(req) + 1;
    if (buf_len > 1) {
        buf = malloc(buf_len);
        if (httpd_req_get_url_query_str(req, buf, buf_len) == ESP_OK) {
            ESP_LOGI(TAG, "Found URL query => %s", buf);
            char param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN], dec_param[EXAMPLE_HTTP_QUERY_KEY_MAX_LEN] = {0};
            /* Get value of expected key from query string */
            if (httpd_query_key_value(buf, "pwm1", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => pwm1=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                pwm1 = atoi(dec_param);
                ESP_LOGI(TAG, "pwm1 integer =%d", pwm1);
                if(comparator != 0)
                {
                    ESP_ERROR_CHECK(mcpwm_comparator_set_compare_value(comparator, pwm1));
                }
                else
                {
                    ESP_LOGE(TAG, "Comparator NULL!");
                }
                
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "pwm2", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => pwm2=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                pwm2 = atoi(dec_param);
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
            if (httpd_query_key_value(buf, "pwm3", param, sizeof(param)) == ESP_OK) {
                ESP_LOGI(TAG, "Found URL query parameter => pwm3=%s", param);
                example_uri_decode(dec_param, param, strnlen(param, EXAMPLE_HTTP_QUERY_KEY_MAX_LEN));
                pwm3 = atoi(dec_param);
                ESP_LOGI(TAG, "Decoded query parameter => %s", dec_param);
            }
        }
        free(buf);
    }

    /* Set some custom headers */
    httpd_resp_set_hdr(req, "Custom-Header-1", "Custom-Value-1");
    httpd_resp_set_hdr(req, "Custom-Header-2", "Custom-Value-2");

    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

char buffer[20000];

static const httpd_uri_t hello = {
    .uri       = "/index.html",
    .method    = HTTP_GET,
    .handler   = hello_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = buffer
};


char buffer2[2000];
static esp_err_t temp_get_handler(httpd_req_t *req)
{
    
    snprintf(buffer2, sizeof(buffer2), "{\"temperature_1\": %f, \"temperature_2\": %f, \"temperature_3\": %f, \"pwm1\": %f, \"pwm2\": %f, \"pwm3\": %f}", (float)temperature_1, (float)temperature_2, (float)temperature_3, (float)pwm1, (float)pwm2, (float)pwm3);
    /* Send response with custom headers and body set as the
     * string passed in user context*/
    const char* resp_str = (const char*) req->user_ctx;
    httpd_resp_send(req, resp_str, HTTPD_RESP_USE_STRLEN);

    /* After sending the HTTP response the old HTTP request
     * headers are lost. Check if HTTP request headers can be read now. */
    if (httpd_req_get_hdr_value_len(req, "Host") == 0) {
        ESP_LOGI(TAG, "Request headers lost");
    }
    return ESP_OK;
}

char buffer2[2000];

static const httpd_uri_t get_temp = {
    .uri       = "/temps",
    .method    = HTTP_GET,
    .handler   = temp_get_handler,
    /* Let's pass response string in user
     * context to demonstrate it's usage */
    .user_ctx  = buffer2
};

/* An HTTP POST handler */
static esp_err_t echo_post_handler(httpd_req_t *req)
{
    char buf[100];
    int ret, remaining = req->content_len;

    while (remaining > 0) {
        /* Read the data for the request */
        if ((ret = httpd_req_recv(req, buf,
                        MIN(remaining, sizeof(buf)))) <= 0) {
            if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
                /* Retry receiving if timeout occurred */
                continue;
            }
            return ESP_FAIL;
        }

        /* Send back the same data */
        httpd_resp_send_chunk(req, buf, ret);
        remaining -= ret;

        /* Log data received */
        ESP_LOGI(TAG, "=========== RECEIVED DATA ==========");
        ESP_LOGI(TAG, "%.*s", ret, buf);
        ESP_LOGI(TAG, "====================================");
    }

    // End response
    httpd_resp_send_chunk(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t echo = {
    .uri       = "/echo",
    .method    = HTTP_POST,
    .handler   = echo_post_handler,
    .user_ctx  = NULL
};

/* This handler allows the custom error handling functionality to be
 * tested from client side. For that, when a PUT request 0 is sent to
 * URI /ctrl, the /hello and /echo URIs are unregistered and following
 * custom error handler http_404_error_handler() is registered.
 * Afterwards, when /hello or /echo is requested, this custom error
 * handler is invoked which, after sending an error message to client,
 * either closes the underlying socket (when requested URI is /echo)
 * or keeps it open (when requested URI is /hello). This allows the
 * client to infer if the custom error handler is functioning as expected
 * by observing the socket state.
 */
esp_err_t http_404_error_handler(httpd_req_t *req, httpd_err_code_t err)
{
    if (strcmp("/hello", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/hello URI is not available");
        /* Return ESP_OK to keep underlying socket open */
        return ESP_OK;
    } else if (strcmp("/echo", req->uri) == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "/echo URI is not available");
        /* Return ESP_FAIL to close underlying socket */
        return ESP_FAIL;
    }
    /* For any other URI send 404 and close socket */
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Some 404 error message");
    return ESP_FAIL;
}

/* An HTTP PUT handler. This demonstrates realtime
 * registration and deregistration of URI handlers
 */
static esp_err_t ctrl_put_handler(httpd_req_t *req)
{
    char buf;
    int ret;

    if ((ret = httpd_req_recv(req, &buf, 1)) <= 0) {
        if (ret == HTTPD_SOCK_ERR_TIMEOUT) {
            httpd_resp_send_408(req);
        }
        return ESP_FAIL;
    }

    if (buf == '0') {
        /* URI handlers can be unregistered using the uri string */
        ESP_LOGI(TAG, "Unregistering /hello and /echo URIs");
        httpd_unregister_uri(req->handle, "/hello");
        httpd_unregister_uri(req->handle, "/echo");
        /* Register the custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, http_404_error_handler);
    }
    else {
        ESP_LOGI(TAG, "Registering /hello and /echo URIs");
        httpd_register_uri_handler(req->handle, &hello);
        httpd_register_uri_handler(req->handle, &echo);
        /* Unregister custom error handler */
        httpd_register_err_handler(req->handle, HTTPD_404_NOT_FOUND, NULL);
    }

    /* Respond with empty body */
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static const httpd_uri_t ctrl = {
    .uri       = "/ctrl",
    .method    = HTTP_PUT,
    .handler   = ctrl_put_handler,
    .user_ctx  = NULL
};

static httpd_handle_t start_webserver(void)
{
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
#if CONFIG_IDF_TARGET_LINUX
    // Setting port as 8001 when building for Linux. Port 80 can be used only by a priviliged user in linux.
    // So when a unpriviliged user tries to run the application, it throws bind error and the server is not started.
    // Port 8001 can be used by an unpriviliged user as well. So the application will not throw bind error and the
    // server will be started.
    config.server_port = 8001;
#endif // !CONFIG_IDF_TARGET_LINUX
    config.lru_purge_enable = true;

    // Start the httpd server
    ESP_LOGI(TAG, "Starting server on port: '%d'", config.server_port);
    if (httpd_start(&server, &config) == ESP_OK) {
        // Set URI handlers
        ESP_LOGI(TAG, "Registering URI handlers");
        httpd_register_uri_handler(server, &hello);
        httpd_register_uri_handler(server, &get_temp);
        httpd_register_uri_handler(server, &ctrl);
        #if CONFIG_EXAMPLE_BASIC_AUTH
        httpd_register_basic_auth(server);
        #endif
        return server;
    }

    ESP_LOGI(TAG, "Error starting server!");
    return NULL;
}

#if !CONFIG_IDF_TARGET_LINUX
static esp_err_t stop_webserver(httpd_handle_t server)
{
    // Stop the httpd server
    return httpd_stop(server);
}

static void disconnect_handler(void* arg, esp_event_base_t event_base,
                               int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server) {
        ESP_LOGI(TAG, "Stopping webserver");
        if (stop_webserver(*server) == ESP_OK) {
            *server = NULL;
        } else {
            ESP_LOGE(TAG, "Failed to stop http server");
        }
    }
}

static void connect_handler(void* arg, esp_event_base_t event_base,
                            int32_t event_id, void* event_data)
{
    httpd_handle_t* server = (httpd_handle_t*) arg;
    if (*server == NULL) {
        ESP_LOGI(TAG, "Starting webserver");
        *server = start_webserver();
    }
}
#endif // !CONFIG_IDF_TARGET_LINUX









#define MAX6675_SO_SIZE_BITS    16
#define MAX6675_SPI_MODE        1
#define MAX6675_TCSS_NS         150
struct max6675_raw_t {
                uint8_t three_state : 1;
                uint8_t device_id : 1;
                uint8_t thermocouple_input : 1;
                uint16_t temperature_reading : 12;
                uint8_t dummy_sign_bit : 1;
            };  
union  {
                uint16_t uint_value;
                struct max6675_raw_t value;
} m_max6675_data;               //!< last read MAX6675 raw data

spi_device_handle_t hspi;
static esp_err_t initialise_SPI()
{
    // For SPI2
    #define PIN_HSPI_MISO 12
    #define PIN_HSPI_MOSI 13
    #define PIN_HSPI_CLK  14
    #define PIN_HSPI_CS0  15

    #define PIN_NUM_MOSI -1
    #define PIN_NUM_MISO PIN_HSPI_MISO
    #define PIN_NUM_CLK  PIN_HSPI_CLK
    #define PIN_NUM_CS   PIN_HSPI_CS0
    #define MAX7765_HOST SPI2_HOST




    esp_err_t ret; //esp_err.h

    gpio_config_t io_conf; //driver/gpio.h

    io_conf.pin_bit_mask = ((1ULL << GPIO_NUM_19) | (1ULL << GPIO_NUM_20) | (1ULL << GPIO_NUM_21));
    io_conf.mode = GPIO_MODE_OUTPUT;      //set as output mode
    io_conf.pull_up_en = 0;                //disable pull-up mode
    io_conf.pull_down_en = 0;              //disable pull-down mode
    io_conf.intr_type = GPIO_INTR_DISABLE; //disable interrupt
    gpio_config(&io_conf);                 //configure GPIO with the given settings



    /*All of spi_bla_bla_function return some value
    *         - ESP_ERR_INVALID_ARG   if parameter is invalid
    *         - ESP_ERR_NOT_FOUND     if host doesn't have any free CS slots
    *         - ESP_ERR_NO_MEM        if out of memory
    *         - ESP_OK                on success
    */ 
    //configure SPI bus for our ESP32 chip
    spi_bus_config_t esp32_bus_config=     //spi_common.h
    { 
    .miso_io_num=PIN_NUM_MISO,
    .mosi_io_num=PIN_NUM_MOSI,
    .sclk_io_num=PIN_NUM_CLK,
    .quadwp_io_num=-1,
    .quadhd_io_num=-1,
    .max_transfer_sz=16 
    };
 
    ret=spi_bus_initialize(MAX7765_HOST, &esp32_bus_config, SPI_DMA_DISABLED); //spi_common.h

    spi_device_interface_config_t max6675_config; //configure struct for MAX6675 (spi_master.h)
    max6675_config.address_bits = 0;
    max6675_config.command_bits = 0;
    max6675_config.dummy_bits = 0;// try to fix the 1 bit lacking issue
    max6675_config.mode = 0;                              
    //max6675_config.duty_cycle_pos = 0;
    max6675_config.cs_ena_posttrans = 0;
    max6675_config.cs_ena_pretrans = 0; 
    max6675_config.clock_speed_hz = 43*1000*1000/10; //Serial Clock Frequency fSCL 4.3 MHz (MAX6675 datasheet)
    max6675_config.spics_io_num = PIN_NUM_CS;
    //max6675_config.flags = 0;
    max6675_config.queue_size = 1;
    max6675_config.pre_cb = NULL;
    max6675_config.post_cb = NULL;
        

    printf("2.Attach the MAX6675 to the SPI bus\n");
    ret=spi_bus_add_device(MAX7765_HOST, &max6675_config, &hspi); //spi_master.h

    if(ret == ESP_OK)
    {
        ESP_LOGI(TAG, "Attach success!");
    }
    else
    {
        ESP_LOGE(TAG, "Attach ERROR!");
    }

    return ret;

}

float read_sensor(int sensor_id)
{
    static spi_transaction_t transaction;
    float temp;
	memset(&transaction, 0, sizeof(transaction));

    transaction.length      = MAX6675_SO_SIZE_BITS; 
    transaction.rxlength    = MAX6675_SO_SIZE_BITS; 
    transaction.flags       = SPI_TRANS_USE_RXDATA; // Read into the transactio rx_data field, do not use DMA.

    gpio_num_t sensor_cs_id = GPIO_NUM_19; 
    if(sensor_id == 1)
    {
        sensor_cs_id = GPIO_NUM_19;
    }
    if(sensor_id == 2)
    {
        sensor_cs_id = GPIO_NUM_20;
    }
    if(sensor_id == 3)
    {
        sensor_cs_id = GPIO_NUM_21;
    }

    

    spi_device_acquire_bus(hspi, portMAX_DELAY);   // Lock out bus use while reading and copying the data
    gpio_set_level(sensor_cs_id, 0);
	assert(spi_device_polling_transmit(hspi, &transaction) == ESP_OK);
    m_max6675_data.uint_value = SPI_SWAP_DATA_RX(*(uint32_t*)transaction.rx_data, 16);    // Copy the raw data
    spi_device_release_bus(hspi);                  // Unlock the bus


    ESP_LOG_BUFFER_HEX_LEVEL(TAG,transaction.rx_data,2,ESP_LOG_DEBUG);
    ESP_LOGI(TAG, "%d ID Sensor (%x %x)- sign bit: %u, temperature: %u, thermocouple_input: %u, device_id: %u, three_state: %u, Temp in °C: %f\n",
                sensor_id,
                (m_max6675_data.uint_value>>8)&0xFF,
                (m_max6675_data.uint_value)&0xFF,
                m_max6675_data.value.dummy_sign_bit,
                m_max6675_data.value.temperature_reading,
                m_max6675_data.value.thermocouple_input,
                m_max6675_data.value.device_id,
                m_max6675_data.value.three_state,
                (float)(m_max6675_data.value.temperature_reading)/4.0);

    temp = (float)(m_max6675_data.value.temperature_reading)/4.0;

    gpio_set_level(sensor_cs_id, 1);

    if (m_max6675_data.value.dummy_sign_bit == 1)
      ESP_LOGE(TAG, "%d ID Sensor - Dummy sign bit is high",
                sensor_id);

    if (m_max6675_data.value.thermocouple_input == 1)
      ESP_LOGE(TAG, "%d ID Sensor - Thermocouple is not connected\n",
                sensor_id);

    return temp;
}


//mcpwm
void mcpwm_setup(){
    ESP_LOGI(TAG, "Create timer and operator");
    
    ESP_ERROR_CHECK(mcpwm_new_timer(&timer_config, &timer));

    
    ESP_ERROR_CHECK(mcpwm_new_operator(&operator_config, &oper));

    ESP_LOGI(TAG, "Connect timer and operator");
    ESP_ERROR_CHECK(mcpwm_operator_connect_timer(oper, timer));

    ESP_LOGI(TAG, "Create comparator and generator from the operator");
    
    ESP_ERROR_CHECK(mcpwm_new_comparator(oper, &comparator_config, &comparator));

    
    ESP_ERROR_CHECK(mcpwm_new_generator(oper, &generator_config, &generator));

    // set the initial compare value, so that the servo will spin to the center position
    ESP_ERROR_CHECK(mcpwm_comparator_set_compare_value(comparator, example_angle_to_compare(0)));

    ESP_LOGI(TAG, "Set generator action on timer and compare event");
    // go high on counter empty
    ESP_ERROR_CHECK(mcpwm_generator_set_action_on_timer_event(generator,
                                                              MCPWM_GEN_TIMER_EVENT_ACTION(MCPWM_TIMER_DIRECTION_UP, MCPWM_TIMER_EVENT_EMPTY, MCPWM_GEN_ACTION_HIGH)));
    // go low on compare threshold
    ESP_ERROR_CHECK(mcpwm_generator_set_action_on_compare_event(generator,
                                                                MCPWM_GEN_COMPARE_EVENT_ACTION(MCPWM_TIMER_DIRECTION_UP, comparator, MCPWM_GEN_ACTION_LOW)));

    ESP_LOGI(TAG, "Enable and start timer");
    ESP_ERROR_CHECK(mcpwm_timer_enable(timer));
    ESP_ERROR_CHECK(mcpwm_timer_start_stop(timer, MCPWM_TIMER_START_NO_STOP));

    
}

void app_main(void)
{
    static httpd_handle_t server = NULL;

    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    snprintf(buffer, sizeof(buffer), "Hello! This is ESP32 HTTP Server. Uptime: %lld seconds", (long long int)(esp_log_timestamp() / 1000));
    mcpwm_setup();

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    /* Register event handlers to stop the server when Wi-Fi or Ethernet is disconnected,
     * and re-start it upon connection.
     */
#if !CONFIG_IDF_TARGET_LINUX
#ifdef CONFIG_EXAMPLE_CONNECT_WIFI
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_WIFI
#ifdef CONFIG_EXAMPLE_CONNECT_ETHERNET
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &connect_handler, &server));
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ETHERNET_EVENT_DISCONNECTED, &disconnect_handler, &server));
#endif // CONFIG_EXAMPLE_CONNECT_ETHERNET
#endif // !CONFIG_IDF_TARGET_LINUX

    /* Start the server for the first time */
    server = start_webserver();
    int cnt = 0;
    initialise_SPI();
    while (1) {
        cnt++;
        if(cnt%5 == 1)
        {
            temperature_1 = read_sensor(1);
        
            temperature_2 = read_sensor(2);
        
            temperature_3 = read_sensor(3);
        }

        

        update_http_response(temperature_1, temperature_2, temperature_3, pwm1, pwm2, pwm3);
        
        
        sleep(1);
    }
}


/**
 * @brief If the power consumption is over the set up limit, the system breaks the main contactor
 * with set_tr_state(0) function. After this need to run the cell_checker_sm() which sets all 14 mcpwm channel is set to -90 degree (all off).
 * After 3 sec of waiting, the system turns on the main contactor with set_tr_state(1) function.
 * If the power consumption is zero, that means we have an electrode short circuit problem, and need to identify the electrode.
 * The procedure is the following: 
 * The system turns off the main contactor and sets the
 * first mcpwm channel to 90 degree and turns it on again. If the power consumption is below the one electrode limit,
 * the electrode is considered as good and the procedure continues with the next electrode.
 * 
 * If an electrode power consumption is above the limit, the system marks it as bad and continues with the next electrode. 
 * The marked electrode is never used again, and the mcpwm channel is set to -90 degree and shall be never changed back to 90.
 * 
 * After the procedure is done with all electrodes, the system turns off the main contactor, sets all not marked electrodes to 90 degree
 * turns on the main contactor and continues with the normal operation.
 * 
 */

#define ZERO_POWER_LIMIT 10
#define ONE_ELECTRODE_LIMIT 100

uint32_t power_consumption()
{
    //read external device;
    return 0;
}

void set_tr_state(int state)
{
    //set external device;
}

void set_angle(int channel, int angle)
{
    //set external device;
}

void cell_checker_sm(void)
{
    static int state = 0;
    static int electrode = 0;
    uint8_t electrode_list[14] = {0};
    static uint32_t last_timestamp = 0;
    uint32_t timestamp = esp_log_timestamp();


    switch(state)
    {
        case 0: // turn off the cell - safety reasons
            set_tr_state(0);
            state = 1;
            break;
        case 1: // in off state remove all power connections from the electrodes
        
            for(int i = 0; i < 14; i++)
            {
                set_angle(i, -90);
            }
            state = 2;
            break;
        case 2: // wait for 3 sec and try again without electrodes   
            if(timestamp - last_timestamp > 3000)
            {
                set_tr_state(1);
                state = 3;
            }
            break;
        case 3: // check the zero electrode consumption
            
            if(power_consumption() < ZERO_POWER_LIMIT)
            {
                set_tr_state(0);
                set_angle(electrode, 90);
                state = 4;
            }
            else
            {
                state = 15; // major error state
            }
            break;
        case 4: // power off and turn on first electrode
            set_tr_state(1);
            
            state = 5;
            break;
        case 5: // check the power consumption of the electrode
            // mark the electrode as bad if the power consumption is above the limit
            if(power_consumption() > ONE_ELECTRODE_LIMIT)
            {
                electrode_list[electrode] = 1;// electrode is bad
            }
            else
            {
                electrode_list[electrode] = 0; // electrode is good
            }
            set_tr_state(0);
            set_angle(electrode, -90);
            state = 6;
            break;
        case 6: 
            electrode++;
            if(electrode == 14)
            {
                set_tr_state(0);
                state = 7;
            }
            else
            {
                state = 3;
            }
            
            break;
        case 7: // turn on the good electrodes
            set_tr_state(0);
            for(int i = 0; i < 14; i++)
            {
                if(electrode_list[i] == 0)
                {
                    set_angle(i, 90);
                }
                else
                {
                    set_angle(i, -90);
                }
            }
            state = 8;
            break;
        case 8: // test finished
            break;
        case 15: // major system failure
            set_tr_state(0);
            break;
    }

    if(state == 8)
    {
        state = 0;
        electrode = 0;
        return;// normal operation
    }
    else
    {
        return; // error/test in progress
    }   


}

 

void update_http_response(float tmp1, float tmp2, float tmp3, int pwm1, int pwm2, int pwm3)
{


    snprintf(buffer, sizeof(buffer),
        "   <script>\r\n \
            var apiUrl = 'http://192.168.43.191/index.html?pwm';\r\n \
            var tempApiUrl = 'http://192.168.43.191/temps';\r\n \
\r\n \
            function pwm1_read() {\r\n \
            var x = document.getElementById(\"pwm1\").value;\r\n \
            document.getElementById(\"demo\").innerHTML = x;\r\n \
            console.log(apiUrl+\"1=\"+x);\r\n \
            fetch(apiUrl+\"1=\"+x).then(response => {\r\n \
              return response.json();\r\n \
            }).then(data => {\r\n \
                // Work with JSON data here\r\n \
              console.log(data);\r\n \
            }).catch(err => {\r\n \
                // Do something for an error here\r\n \
            });\r\n \
            }\r\n \
\r\n \
            function pwm2_read() {\r\n \
            var x = document.getElementById(\"pwm2\").value;\r\n \
            document.getElementById(\"demo\").innerHTML = x;\r\n \
            console.log(apiUrl+\"2=\"+x);\r\n \
            fetch(apiUrl+\"2=\"+x).then(response => {\r\n \
              return response.json();\r\n \
            }).then(data => {\r\n \
                // Work with JSON data here \r\n \
              console.log(data);\r\n \
            }).catch(err => {\r\n \
                // Do something for an error here \r\n \
            });\r\n \
            }\r\n \
\r\n \
            function pwm3_read() {\r\n \
            var x = document.getElementById(\"pwm3\").value;\r\n \
            document.getElementById(\"demo\").innerHTML = x;\r\n \
            console.log(apiUrl+\"3=\"+x);\r\n \
            fetch(apiUrl+\"3=\"+x).then(response => {\r\n \
              return response.json();\r\n \
            }).then(data => {\r\n \
                // Work with JSON data here\r\n \
              console.log(data);\r\n \
            }).catch(err => {\r\n \
                // Do something for an error here\r\n \
            });\r\n \
            }\r\n \
\r\n \
\r\n \
            function read_periodic_data(){\r\n \
            //window.location.reload(1);\r\n \
            \r\n \
            fetch(tempApiUrl).then(response => {\r\n \
              return response.json();\r\n \
            }).then(data => {\r\n \
                var inc_text = \"Temp 1: \"+data.temperature_1+\"<br> Temp 2: \"+data.temperature_2+\"<br> Temp 3: \"+data.temperature_3+\"<br> PWM 1: \"+data.pwm1+\"<br> PWM 2: \"+data.pwm2+\"<br> PWM 3: \"+data.pwm3;\r\n \
                document.getElementById(\"actual_data\").innerHTML = inc_text; \r\n \
              console.log(data);\r\n \
            }).catch(err => {\r\n \
                // Do something for an error here\r\n \
            });\r\n \
            setTimeout(read_periodic_data, 1000);\r\n \
            }\r\n \
\r\n \
            setTimeout(read_periodic_data, 1000);\r\n \
            </script>\r\n \
            <p id=\"actual_data\">Temp 1: %f<br> Temp 2: %f<br> Temp 3: %f<br> PWM 1: %d<br> PWM 2: %d<br> PWM 3: %d</p> <p>Last sent</p>\r\n \
            <p id=\"demo\"></p>\r\n \
            <p >PWM1</p>\r\n \
            <input type=\"text\" id=\"pwm1\" value=\"%d\">\r\n \
\r\n \
            <button onclick=\"pwm1_read()\">SEND</button>\r\n \
\r\n \
            <p id=\"3\">PWM2</p>\r\n \
            <input type=\"text\" id=\"pwm2\" value=\"%d\">\r\n \
\r\n \
            <button onclick=\"pwm2_read()\">SEND</button>\r\n \
\r\n \
            <p id=\"4\">PWM3</p>\r\n \
            <input type=\"text\" id=\"pwm3\" value=\"%d\">\r\n \
\r\n \
            <button onclick=\"pwm3_read()\">SEND</button>\r\n \
\r\n \
            <p id=\"5\"></p>\r\n ", tmp1, tmp2, tmp3, pwm1, pwm2, pwm3, pwm1, pwm2, pwm3);

}