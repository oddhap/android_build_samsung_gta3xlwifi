#include <cassert>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#define ALOGE(...) ((void)0)
#define STATS_MAP_SIZE 5000
constexpr int PER_UID_STATS_ENTRIES_LIMIT = 500;
constexpr int TOTAL_UID_STATS_ENTRIES_LIMIT = STATS_MAP_SIZE * 0.9;
static int check(uint32_t totalEntryCount,uint32_t perUidEntryCount){
 constexpr uint32_t mTotalUidStatsEntriesLimit=TOTAL_UID_STATS_ENTRIES_LIMIT;
 constexpr uint32_t mPerUidStatsEntriesLimit=PER_UID_STATS_ENTRIES_LIMIT;
    if (totalEntryCount > mTotalUidStatsEntriesLimit ||
        perUidEntryCount > mPerUidStatsEntriesLimit) {
        ALOGE("Too many stats entries in the map, total count: %u, chargeUid(%u) count: %u,"
              " blocking tag request to prevent map overflow",
              totalEntryCount, chargeUid, perUidEntryCount);
        return -EMFILE;
    }

 return 0;
}
int main(){assert(PER_UID_STATS_ENTRIES_LIMIT==500&&TOTAL_UID_STATS_ENTRIES_LIMIT==4500);uint32_t values[]={0,499,500,501,4499,4500,4501,5000,UINT32_MAX};unsigned cases=0;for(auto all:values)for(auto uid:values){assert(check(all,uid)==((all>4500||uid>500)?-EMFILE:0));++cases;}printf("passed_cases=%u per_uid_limit=500 total_limit=4500\n",cases);}
