#include "sniffer.h"

Sniffer::Sniffer()
{
}

void Sniffer::StartSniffer()
{
    pcap_pkthdr* Header;
    const u_char* PacketData;

    run = true;

    while(run)
    {
        int res = pcap_next_ex(DevHandle,&Header,&PacketData);
        int Pktlen = 0; // check packet len

        if(res < 0) // pcap_next_ex Error
        {
            QMessageBox::information(NULL,"ERROR","pcap_next_ex Error");
            break;
        }

        struct ieee80211_radiotap_header *RadioHdr = (struct ieee80211_radiotap_header *)PacketData;
        Pktlen += RadioHdr->it_len; //if you want Radiotap analyze then go Wireless_Sniffer_Console version


        struct ApInfo apInfo;
        struct ieee80211_MacFrame *ieeeMacFrameHeader = (struct ieee80211_MacFrame*)(PacketData + Pktlen);

        __u8 FrameType;
        __u8 Type;
        __u8 SubType;

        FrameType = ieeeMacFrameHeader->FrameControl_Type;
       // memcpy(&FrameType,ieeeMacFrameHeader->FrameControl_Type,sizeof(__u8));
        Type = (FrameType >> 2) & 3;
        SubType = FrameType >> 4;


        __u8 Flag;
        //memcpy(&Flag,ieeeMacFrameHeader->FrameControl_Flag,sizeof(__u8));
        Flag = ieeeMacFrameHeader->FrameControl_Flag;

        int n = 1;
        bool Capabilities[8] = {false};
        apInfo._enc = "OPEN";

        for(int i = 0 ; i<8 ; i++) {

            Capabilities[i] = (Flag & (n << i) ? true : false);
            if(i == 0); // Staiton  -> AP
            else if(i == 1); // AP-> Staiton
            else if(i == 2); // More Fragments
            else if(i == 3); // Retry
            else if(i == 4); // PWR MGT
            else if(i == 5); // More Data
            else if(i == 6) // Protected flag -> if 0 then enc OPEN mode
            {
                if(Capabilities[i]) apInfo._enc = "WEP";
            }
            else if(i == 7); // Order flag

        }

        // 802.11 MAC Frame

        if(Type == 0 && (SubType == 5 || SubType == 8)) // Maneged Frame(beacon, probeResponse, Data
        {

            // if Type == 1 ( Control Frmae ) this Optional
            Pktlen += (sizeof(struct ieee80211_MacFrame)+12); // Fixed Paramerter + 80211 MacHeader
            memcpy(&apInfo._bssid,ieeeMacFrameHeader->BssId, 6* sizeof(__u8));


            while(Pktlen < (int)Header->len)
            {
                __u8 tag_id;
                memcpy(&tag_id,PacketData+Pktlen,sizeof(__u8));
                Pktlen += sizeof(__u8);

                __u8 tag_length;
                memcpy(&tag_length,PacketData+Pktlen,sizeof(__u8));
                Pktlen += sizeof(__u8);

                switch((int)tag_id) {

                case 0:
                    char char_temp[255];
                    memcpy(char_temp,(PacketData+Pktlen),(int)tag_length);
                    apInfo._ssid.assign(char_temp,(int)tag_length);
                    break;
                case 3:
                    __u8 temp_channel;
                    memcpy(&temp_channel,PacketData+Pktlen,sizeof(__u8));
                    apInfo._channel = (int)temp_channel;
                    break;
                case 48:
                    apInfo._enc = "WPA2";
                    break;

                case 221:
                    __u8 check_wpa[6];
                    memcpy(check_wpa,PacketData+Pktlen,(6 *sizeof(__u8)));
                    if(check_wpa[0] == 0x00 && check_wpa[1] == 0x50 && check_wpa[2] == 0xf2
                            && check_wpa[3] == 0x01 && check_wpa[4] == 0x01 && check_wpa[5] == 0x00)
                    {
                        if(apInfo._enc == "WPA2") apInfo._enc="WPA/WPA2";
                        else apInfo._enc = "WPA";
                    }
                    break;
                }

                Pktlen += (int)tag_length;

            }

        }


        else if(Type == 1) // This if Contrrol Fame 11 specices
        {

        }

        else if(Type == 2) // This is Data Frame
        {

            if((Capabilities[0]) && (!Capabilities[1])) // mobile -> APStation
            {
                memcpy(apInfo.station_addr,ieeeMacFrameHeader->DesAddress,6 * sizeof(__u8));
                memcpy(apInfo._bssid,ieeeMacFrameHeader->SrcAddress,6 * sizeof(__u8));
            }

            else if(!(Capabilities[0]) && (Capabilities[1])) // mobile -> APStation
            {
                memcpy(apInfo.station_addr,ieeeMacFrameHeader->SrcAddress,6 * sizeof(__u8));
                memcpy(apInfo._bssid,ieeeMacFrameHeader->DesAddress,6 * sizeof(__u8));
            }

        }

        emit CapturePacket(apInfo);
    }

}

void Sniffer::StopSniffer()
{
     run = false;
}
