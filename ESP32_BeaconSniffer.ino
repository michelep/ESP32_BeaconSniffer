// ESP32 WiFi beacon sniffer
//
// by Michele <o-zone@zerozone.it> Pinassi
// https://github.com/michelep/ESP32_BeaconSniffer
//
// Sighly based on https://github.com/ESP-EOS/ESP32-WiFi-Sniffer, code written to work on ESP32 TTGO with OLED display SSD1306 I2C 
//
// Build with TTGO-LoRa32-OLED V1 Arduino template
// 
// https://www.espressif.com/en/products/hardware/esp32-devkitc/resources

#include "freertos/FreeRTOS.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"

#include "logo.h"

// OLED LCD display
// https://github.com/igrr/esp8266-oled-ssd1306
#include <Wire.h>
#include "SSD1306.h"

#define I2C_SCL 4
#define I2C_SDA 5

#define DISPLAY_MAX_W 128
#define DISPLAY_MAX_H 64

SSD1306 display(0x3c, I2C_SDA, I2C_SCL);
//
#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

uint8_t level = 0, channel = 1;

static wifi_country_t wifi_country = {.cc="IT", .schan = 1, .nchan = 13}; // Most recent esp32 library struct

typedef struct {
  unsigned protocol:2;
  unsigned type:2;
  unsigned subtype:4;
  unsigned to_ds:1;
  unsigned from_ds:1;
  unsigned more_frag:1;
  unsigned retry:1;
  unsigned pwr_mgmt:1;
  unsigned more_data:1;
  unsigned wep:1;
  unsigned strict:1;
} wifi_header_frame_control_t;

// https://carvesystems.com/news/writing-a-simple-esp8266-based-sniffer/
typedef struct {
  wifi_header_frame_control_t frame_ctrl;
  unsigned duration_id:16;
  uint8_t addr1[6]; /* receiver MAC address */
  uint8_t addr2[6]; /* sender MAC address */
  uint8_t addr3[6]; /* BSSID filtering address */
  unsigned sequence_ctrl:16;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;


typedef struct
{
  unsigned interval:16;
  unsigned capability:16;
  unsigned tag_number:8;
  unsigned tag_length:8;
  char ssid[0];
  uint8_t rates[1];
} wifi_beacon_hdr;

typedef struct {
  uint8_t mac[6];
} __attribute__((packed)) mac_addr;


typedef enum
{
    ASSOCIATION_REQ,
    ASSOCIATION_RES,
    REASSOCIATION_REQ,
    REASSOCIATION_RES,
    PROBE_REQ,
    PROBE_RES,
    NU1,  /* ......................*/
    NU2,  /* 0110, 0111 not used */
    BEACON,
    ATIM,
    DISASSOCIATION,
    AUTHENTICATION,
    DEAUTHENTICATION,
    ACTION,
    ACTION_NACK,
} wifi_mgmt_subtypes_t;

static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);

esp_err_t event_handler(void *ctx, system_event_t *event)
{
  return ESP_OK;
}

void wifi_sniffer_init(void)
{
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_NULL) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel)
{
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}

void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type) {
  if (type != WIFI_PKT_MGMT)
    return;

  // https://blog.podkalicki.com/wp-content/uploads/2017/01/esp32_promiscuous_pkt_structure.jpeg
  const wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  const wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  const wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;

  // From https://github.com/SHA2017-badge/bpp/blob/master/esp32-recv/main/bpp_sniffer.c 
  // https://github.com/n0w/esp8266-simple-sniffer/blob/master/src/main.cpp
  char ssid[32] = {0};
  
  const wifi_header_frame_control_t *fctl = (wifi_header_frame_control_t *)&hdr->frame_ctrl;
  
  // Details about beacon frames: https://mrncciew.com/2014/10/08/802-11-mgmt-beacon-frame/
  if(fctl->subtype == BEACON) { //beacon
    wifi_beacon_hdr *beacon=(wifi_beacon_hdr*)ipkt->payload;

    if(beacon->tag_length >= 32) {
      strncpy(ssid, beacon->ssid, 31);
    } else {
      strncpy(ssid, beacon->ssid, beacon->tag_length);
    }
    Serial.printf("Beacon %s\n",ssid);
    addBeacon(ssid, ppkt->rx_ctrl.channel, ppkt->rx_ctrl.rssi);
  }

  printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d,"
    " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
    " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
    wifi_sniffer_packet_type2str(type),
    ppkt->rx_ctrl.channel,
    ppkt->rx_ctrl.rssi,
    // ADDR1
    hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
    hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
    // ADDR2
    hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
    hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
    // ADDR3
    hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
    hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
  );
}
// ************************************
// DEBUG()
//
// ************************************
#define __DEBUG__

void DEBUG(String message) {
#ifdef __DEBUG__
  Serial.println(message);
#endif
}


#include <LinkedList.h>

class WiFiBeacon {
  public:
    char name[32];
    int rssi;
    uint8_t channel;
    char mac[6]; 
    uint8_t lastseen;
};

LinkedList<WiFiBeacon*> myBeacons = LinkedList<WiFiBeacon*>();

void addBeacon(char ssid[],uint8_t channel, int rssi) {
  WiFiBeacon *beacon;
  for(int i = 0; i < myBeacons.size(); i++) {
    beacon = myBeacons.get(i); 
    if(strncmp(beacon->name,ssid,32)==0) {
      // update beacon data and return
      beacon->rssi = rssi;
      beacon->channel = channel;
      beacon->lastseen = 0;
      Serial.printf("Update beacon %s\n",ssid);
      return;
    }
  }
  // add new beacon  
  beacon = new WiFiBeacon();
  strncpy(beacon->name,ssid,32);
  beacon->rssi = rssi;
  beacon->lastseen = 0;
  myBeacons.add(beacon);
  Serial.printf("Add new beacon %s on channel %d\n",ssid,channel);
}

hw_timer_t *timer = NULL;
bool timerChannel=false;

void IRAM_ATTR onTimer(){
  timerChannel=true;
}

// the setup function runs once when you press reset or power the board
void setup() {
  Serial.begin(115200);
  delay(10);
  // Initialize OLED display
  display.init();
  display.drawXbm(0, 0, logo_width, logo_height, logo_bits);
  display.display();
  delay(5000);
  
  wifi_sniffer_init();

  timer = timerBegin(0, 80, true);
  timerAttachInterrupt(timer, &onTimer, true);
  timerAlarmWrite(timer, 1000000, true);
  timerAlarmEnable(timer);
}

// the loop function runs over and over again forever
void loop() {
  if(timerChannel) {
     WiFiBeacon *beacon;
        
    // Age for all beacons detected...
    for(int i = 0; i < myBeacons.size(); i++) {
      beacon = myBeacons.get(i); 
      beacon->lastseen++;
      if(beacon->lastseen > 60) {
        // older that 60 secs? remove it!
        Serial.printf("Remove lost beacon %s\n",beacon->name);
        myBeacons.remove(i);
      }
    }

    // Set channel
    wifi_sniffer_set_channel(channel);
    channel = (channel % WIFI_CHANNEL_MAX) + 1;

    // Update display
    display.clear();
    display.setColor(WHITE);
    display.drawHorizontalLine(0, 0, round((DISPLAY_MAX_W / WIFI_CHANNEL_MAX)*channel));
    display.drawHorizontalLine(0, 1, round((DISPLAY_MAX_W / WIFI_CHANNEL_MAX)*channel));

    display.setTextAlignment(TEXT_ALIGN_CENTER);
    display.drawString(64, 2, String(channel));
    display.drawHorizontalLine(0, 14, DISPLAY_MAX_W);
    display.setTextAlignment(TEXT_ALIGN_LEFT);
    display.drawString(0, 16, "Total APs: "+String(myBeacons.size()));

    // Display the 4 nearest APs..
    for(int i=0; i<4; i++) {
      beacon = myBeacons.get(i); 
      display.drawString(0, 26+(10*i), String(beacon->name));
    }

    display.display();

    timerChannel=false;
  }
}
