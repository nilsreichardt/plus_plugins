#include "include/connectivity_plus_windows/connectivity_windows_plugin.h"

#pragma comment(lib, "wlanapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

// This must be included before many other Windows headers.
#define _WIN32_WINNT _WIN32_WINNT_VISTA
#define NTDDI_VERSION NTDDI_VISTA
#define WIN32_LEAN_AND_MEAN
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <windows.h>
#include <netlistmgr.h>
#include <comdef.h>
#include <comip.h>
#include <wlanapi.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

#include <flutter/method_channel.h>
#include <flutter/event_channel.h>
#include <flutter/event_stream_handler_functions.h>
#include <flutter/plugin_registrar_windows.h>
#include <flutter/standard_method_codec.h>

#include <map>
#include <memory>
#include <sstream>
#include <iomanip>

namespace {

  class ConnectivityWindowsPlugin : public flutter::Plugin {
    public:
      static void RegisterWithRegistrar(flutter::PluginRegistrarWindows *registrar);

      ConnectivityWindowsPlugin();

      virtual ~ConnectivityWindowsPlugin();

    private:
      // Called when a method is called on this plugin's channel from Dart.
      void HandleMethodCall(
        const flutter::MethodCall <flutter::EncodableValue> &method_call,
        std::unique_ptr <flutter::MethodResult<flutter::EncodableValue>> result);

      void HandleOnListen(std::unique_ptr <flutter::EventSink<flutter::EncodableValue>> &&events);

      void HandleOnCancel();

      std::string getNetworkType();
      std::string getWifiName();
      std::string getWifiBSSID();
      std::string getWifiIPAddress();

      bool bInitialized = false;
      _com_ptr_t <_com_IIID<INetworkListManager, &__uuidof(INetworkListManager)>> mNetListMgr;
      std::unique_ptr <flutter::EventSink<flutter::EncodableValue>> mEventSink;
  };

// static
  void ConnectivityWindowsPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarWindows *registrar) {

    auto plugin = std::make_unique<ConnectivityWindowsPlugin>();

    auto methodChannel =
      std::make_unique < flutter::MethodChannel < flutter::EncodableValue >> (
        registrar->messenger(), "plugins.flutter.io/connectivity",
          &flutter::StandardMethodCodec::GetInstance());

    auto eventChannel =
      std::make_unique < flutter::EventChannel < flutter::EncodableValue >> (
        registrar->messenger(), "plugins.flutter.io/connectivity_status",
          &flutter::StandardMethodCodec::GetInstance());

    methodChannel->SetMethodCallHandler(
      [plugin_pointer = plugin.get()](const auto &call, auto result) {
        plugin_pointer->HandleMethodCall(call, std::move(result));
      });

    auto streamHandler =
      std::make_unique < flutter::StreamHandlerFunctions < flutter::EncodableValue >> (
        [plugin_pointer = plugin.get()](const flutter::EncodableValue *arguments,
                                        std::unique_ptr <flutter::EventSink<flutter::EncodableValue>> &&events)
          -> std::unique_ptr <flutter::StreamHandlerError<flutter::EncodableValue>> {
          plugin_pointer->HandleOnListen(std::move(events));
          return nullptr;
        },
          [plugin_pointer = plugin.get()](const flutter::EncodableValue *arguments)
            -> std::unique_ptr <flutter::StreamHandlerError<flutter::EncodableValue>> {
            plugin_pointer->HandleOnCancel();
            return nullptr;
          });

    eventChannel->SetStreamHandler(std::move(streamHandler));

    registrar->AddPlugin(std::move(plugin));
  }

  ConnectivityWindowsPlugin::ConnectivityWindowsPlugin() {
    HRESULT hr;

    hr = CoInitializeEx(NULL, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) {
      hr = CoCreateInstance(CLSID_NetworkListManager, NULL, CLSCTX_ALL, IID_INetworkListManager, (LPVOID *)&mNetListMgr);
      if (SUCCEEDED(hr)) {
        bInitialized = true;
      }
    }
  }

  ConnectivityWindowsPlugin::~ConnectivityWindowsPlugin() {
    if (bInitialized) {
      CoUninitialize();
    }
  }

  void ConnectivityWindowsPlugin::HandleMethodCall(
    const flutter::MethodCall <flutter::EncodableValue> &method_call,
    std::unique_ptr <flutter::MethodResult<flutter::EncodableValue>> result) {
    // Replace "getPlatformVersion" check with your plugin's method.
    // See:
    // https://github.com/flutter/engine/tree/master/shell/platform/common/cpp/client_wrapper/include/flutter
    // and
    // https://github.com/flutter/engine/tree/master/shell/platform/glfw/client_wrapper/include/flutter
    // for the relevant Flutter APIs.

    std::string method = method_call.method_name();
    if (method.compare("check") == 0) {
      flutter::EncodableValue response(getNetworkType());
      result->Success(&response);
    }
    else if(method == "wifiName") {
      flutter::EncodableValue response(getWifiName());
      result->Success(&response);
    }
    else if(method == "wifiBSSID") {
      flutter::EncodableValue response(getWifiBSSID());
      result->Success(&response);
    }
    else if(method == "wifiIPAddress") {
      flutter::EncodableValue response(getWifiIPAddress());
      result->Success(&response);
    }
    else {
      result->NotImplemented();
    }
  }

  void ConnectivityWindowsPlugin::HandleOnListen(
    std::unique_ptr <flutter::EventSink<flutter::EncodableValue>> &&events) {
    std::cout << "ConnectivityWindowsPlugin onListen";
    mEventSink = std::move(events);
    flutter::EncodableValue response(getNetworkType());
    mEventSink->Success(&response);
  }

  void ConnectivityWindowsPlugin::HandleOnCancel() {
    //
  }

  std::string ConnectivityWindowsPlugin::getNetworkType() {
    std::string result = "none";
    if(bInitialized) {
      VARIANT_BOOL bState = FALSE;
      HRESULT hr = mNetListMgr->get_IsConnectedToInternet(&bState);
      if (SUCCEEDED(hr)) {
        if(bState == VARIANT_TRUE) {
          result = "wifi";
        }
      }
    }
    return result;
  }

  std::string ConnectivityWindowsPlugin::getWifiName() {
    std::ostringstream result;
    HANDLE hClientHandle;
    DWORD dwNegotiatedVersion = WLAN_API_MAKE_VERSION(2, 0);
    if(WlanOpenHandle(WLAN_API_VERSION, NULL, &dwNegotiatedVersion, &hClientHandle) == ERROR_SUCCESS){
      WLAN_INTERFACE_INFO_LIST *pInterfaces = NULL;
      if(WlanEnumInterfaces(hClientHandle, NULL, &pInterfaces) == ERROR_SUCCESS){
        for(DWORD i = 0; i < pInterfaces->dwNumberOfItems; i++) {
          GUID *pGuid = &pInterfaces->InterfaceInfo[i].InterfaceGuid;
          DWORD dwDataSize = 0;
          WLAN_CONNECTION_ATTRIBUTES *pData;
          if(WlanQueryInterface(hClientHandle, pGuid, wlan_intf_opcode_current_connection, NULL, &dwDataSize, (LPVOID *)&pData, NULL) == ERROR_SUCCESS){
            if(pData->isState == wlan_interface_state_connected) {
              PDOT11_SSID ssid = &pData->wlanAssociationAttributes.dot11Ssid;
              std::string strSSID((const char *) ssid->ucSSID, ssid->uSSIDLength);
              result << strSSID;
              WlanFreeMemory(pData);
              break;
            }
            WlanFreeMemory(pData);
          }
        }
        WlanFreeMemory(pInterfaces);
      }
      WlanCloseHandle(hClientHandle, NULL);
    }
    return result.str();
  }

  std::string ConnectivityWindowsPlugin::getWifiBSSID() {
    std::ostringstream result;
    HANDLE hClientHandle;
    DWORD dwNegotiatedVersion = WLAN_API_MAKE_VERSION(2, 0);
    if(WlanOpenHandle(WLAN_API_VERSION, NULL, &dwNegotiatedVersion, &hClientHandle) == ERROR_SUCCESS){
      WLAN_INTERFACE_INFO_LIST *pInterfaces = NULL;
      if(WlanEnumInterfaces(hClientHandle, NULL, &pInterfaces) == ERROR_SUCCESS){
        for(DWORD i = 0; i < pInterfaces->dwNumberOfItems; i++) {
          GUID *pGuid = &pInterfaces->InterfaceInfo[i].InterfaceGuid;
          DWORD dwDataSize = 0;
          WLAN_CONNECTION_ATTRIBUTES *pData;
          if(WlanQueryInterface(hClientHandle, pGuid, wlan_intf_opcode_current_connection, NULL, &dwDataSize, (LPVOID *)&pData, NULL) == ERROR_SUCCESS){
            if(pData->isState == wlan_interface_state_connected) {
              result << std::hex << std::setfill('0');
              for (DWORD j = 0; j < 6; j++) {
                result << std::setw(2) << static_cast<unsigned>(pData->wlanAssociationAttributes.dot11Bssid[j]) << ":";
              }
              WlanFreeMemory(pData);
              break;
            }
            WlanFreeMemory(pData);
          }
        }
        WlanFreeMemory(pInterfaces);
      }
      WlanCloseHandle(hClientHandle, NULL);
    }
    return result.str();
  }

  std::string ConnectivityWindowsPlugin::getWifiIPAddress() {
    std::ostringstream result;
    HANDLE hClientHandle;
    DWORD dwNegotiatedVersion = WLAN_API_MAKE_VERSION(2, 0);
    if(WlanOpenHandle(WLAN_API_VERSION, NULL, &dwNegotiatedVersion, &hClientHandle) == ERROR_SUCCESS){
      WLAN_INTERFACE_INFO_LIST *pInterfaces = NULL;
      if(WlanEnumInterfaces(hClientHandle, NULL, &pInterfaces) == ERROR_SUCCESS){
        for(DWORD i = 0; i < pInterfaces->dwNumberOfItems; i++) {
          GUID *pGuid = &pInterfaces->InterfaceInfo[i].InterfaceGuid;
          DWORD dwDataSize = 0;
          WLAN_CONNECTION_ATTRIBUTES *pData;
          if(WlanQueryInterface(hClientHandle, pGuid, wlan_intf_opcode_current_connection, NULL, &dwDataSize, (LPVOID *)&pData, NULL) == ERROR_SUCCESS){
            if(pData->isState == wlan_interface_state_connected) {
              bool found = false;
              IF_LUID ifLuid;
              ConvertInterfaceGuidToLuid(pGuid, &ifLuid); // FIXME check return
              ULONG ulSize = 0;
              GetAdaptersAddresses(AF_INET, 0, NULL, NULL, &ulSize);
              IP_ADAPTER_ADDRESSES *pIpAdapterAddresses = (IP_ADAPTER_ADDRESSES *)HeapAlloc(GetProcessHeap(), 0, ulSize);
              if(GetAdaptersAddresses(AF_UNSPEC, 0, NULL, pIpAdapterAddresses, &ulSize) == 0) {
                IP_ADAPTER_ADDRESSES *pCurrent = pIpAdapterAddresses;
                while(pCurrent != NULL) {
                  if(pCurrent->Luid.Value == ifLuid.Value) {
                    CHAR buffer[64];
                    PIP_ADAPTER_UNICAST_ADDRESS_LH pAddr = pCurrent->FirstUnicastAddress;
                    while(pAddr->Next != NULL) {
                      pAddr = pAddr->Next;
                    }
                    sockaddr_in *sa_in = (sockaddr_in *) pAddr->Address.lpSockaddr;
                    result << inet_ntop(AF_INET, &(sa_in->sin_addr), buffer, 64);
                    found = true;
                    break;
                  }
                  pCurrent = pCurrent->Next;
                }
              }
              HeapFree(GetProcessHeap(), 0, pIpAdapterAddresses);
              if(found) {
                //RtlIpv4AddressToStringA(&row.Address);
                //std::string strSSID((const char *) ssid->ucSSID, ssid->uSSIDLength);

                WlanFreeMemory(pData);
                break;
              }
            }
            WlanFreeMemory(pData);
          }
        }
        WlanFreeMemory(pInterfaces);
      }
      WlanCloseHandle(hClientHandle, NULL);
    }
    return result.str();
  }

}  // namespace

void ConnectivityWindowsPluginRegisterWithRegistrar(
  FlutterDesktopPluginRegistrarRef registrar) {
  ConnectivityWindowsPlugin::RegisterWithRegistrar(
    flutter::PluginRegistrarManager::GetInstance()
      ->GetRegistrar<flutter::PluginRegistrarWindows>(registrar));
}
