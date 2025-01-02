#include <vector>
#include <cmath>
#include <cstdint>
#include <string>
#include <iostream>
#include <sstream>
#include <unordered_map>
#include <fstream>
#include <cassert>
#include <iomanip>

#define ADDRESS_SIZE 32

class md_entry{
public:
    int tag;
    bool valid;
    bool dirty;
    uint32_t address;

    md_entry(): tag(0), valid(0), dirty(0), address(0){}

};

class LRU_entry{
public:
    int way;
    bool valid;
    LRU_entry(): way(0), valid(0){}

};

class cache{
public:
    int access_time;
    int cache_size;
    int block_size;
    int set_size;
    int ways;
    int tag_size;
    int total_accesses;
    int hit_accesses;
    std::vector<std::vector<md_entry>> metadata;
    std::vector<std::vector<LRU_entry>> LRU_metadata;

    cache(int access_time_param, int cache_log_size, int block_log_size, int assoc_level)
    {
        access_time = access_time_param;
        cache_size = cache_log_size;
        block_size = block_log_size;
        set_size = cache_log_size - assoc_level - block_log_size;
        tag_size = ADDRESS_SIZE - set_size - block_size;
        ways = std::pow(2, assoc_level);
        total_accesses = 0;
        hit_accesses = 0;

        LRU_metadata.resize(std::pow(2, set_size), std::vector<LRU_entry>(ways));

        metadata.resize(ways, std::vector<md_entry>(std::pow(2, set_size)));
    }

    bool exist(instruction inst);
    bool free_set_entry(uint32_t address);
    uint32_t evict_entry(uint32_t address);
    void update_lru(uint32_t address);
    void remove_from_lru(uint32_t address);
    uint32_t load_to_cache(uint32_t address);
    void remove_from_cache(uint32_t address);
};


enum instruction_type{
    READ,
    WRITE,
};

class instruction {
public:
    enum instruction_type type;
    uint32_t address;
};

class simulator{
public:
    cache l1;
    cache l2;
    bool write_allocate;
    int total_cycles;
    int mem_access_time;
    std::vector<instruction> instructions_vec;

    simulator() 
    : l1(0, 0, 0, 0), 
      l2(0, 0, 0, 0), 
      write_allocate(false), 
      total_cycles(0), 
      mem_access_time(0) {}

    void parse_input(int argc, char *argv[]);
    void run_simulator();
    int read(instruction inst);
    int write(instruction inst);
    void print_instruction(uint32_t address);
};
