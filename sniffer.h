#ifndef SNIFFER_H
#define SNIFFER_H

#include <QObject>
#include <string>
#include <QString>
#include <deviceselector.h>
#include "ieee80211_radiotap.h"


#pragma pack(push,1)
struct ApInfo
{
    std::string _ssid; // ssid name
    int _channel; // channel name
    std::string  _enc; // encrypt
    int data_count; // data count
    __u8 station_addr[6]; // station addr
    __u8 _bssid[6]; // bssid

};

struct ieee80211_MacFrame
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    __u8 FrameControl_Type;
    __u8 FrameControl_Flag;
#endif
#if __BYTE_ORDER == __BIG_ENDIAN
    __u8 FrameControl_Flag;
    __u8 FrameControl_Type;
#endif
    __le16 Duration;

    __u8 DesAddress[6];
    __u8 SrcAddress[6];
    __u8 BssId[6];

    __le16 SequenceControl;

};

#pragma pack(pop)

class Sniffer : public QObject
{
    Q_OBJECT

public:
    Sniffer();
    void SetHandle(pcap_t *_DevHandle) { DevHandle = _DevHandle; }

    bool run;

private:
    pcap_t* DevHandle;


signals:
    void CapturePacket(struct ApInfo _apinfo);
    void PlusPacketNum();

public slots:
    void StartSniffer();
    void StopSniffer();

};

#endif // SNIFFER_H
