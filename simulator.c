#include "simulator.h"
#include <assert.h>

#define DEBUG_MODE 1
#if DEBUG_MODE
    #define DEBUG_PRINT(...) std::cout << __VA_ARGS__ << std::endl;
#else
    #define DEBUG_PRINT(...)
#endif

// check if the tag of the address is in the cache
bool cache::exist(instruction inst)
{
    int way = 0; // for PRINT_DEBUG
    for(std::vector<md_entry> &way_vector : metadata)
    {   
        int index = tag_size + block_size == 32 ? 0 : (address << tag_size) >> (tag_size + block_size);
        md_entry &entry = way_vector[index];
        if(entry.valid && entry.tag == (address >> (set_size + block_size)))
        {
            DEBUG_PRINT("exist:: address = " << std::hex << address << std::dec << ", way = " << way << ", found\n");
            if (inst.type == WRITE)
            {
                entry.dirty = true;
            }
            return true;
        }
        way++;
    }
    DEBUG_PRINT("exist:: address = " << std::hex << address << std::dec << ", DIDNT find\n");
    return false;
}

// iterate through all the ways and check if there is a free spot in the specific set
bool cache::free_set_entry(uint32_t address)
{
    for(std::vector<md_entry> &way_vector : metadata)
    {
        int index = tag_size + block_size == 32 ? 0 : (address << tag_size) >> (tag_size + block_size);
        md_entry &entry = way_vector[index];
        if(!entry.valid)
        {
            return true;
        }
    }

    return false;
}


//check if we should evict an entry from the cache and return the address of the evicted entry.
uint32_t cache::evict_entry(uint32_t address)
{
    uint32_t swapped_out_address;
    bool free_set_entry_found = free_set_entry(address);
    if (free_set_entry_found)
    {
        DEBUG_PRINT("No need to evict - free spot in the set");
        return 0;
    }

    int index = tag_size + block_size == 32 ? 0 : (address << tag_size) >> (tag_size + block_size);
    int lru_way = LRU_metadata[index].back().way;
    DEBUG_PRINT("Evicting way " << lru_way);
    remove_from_lru(metadata[lru_way][index].address);
    DEBUG_PRINT("Evicting address " << std::hex << metadata[lru_way][index].address << std::dec);
    metadata[lru_way][index].valid = false;
    swapped_out_address = metadata[lru_way][index].address;
    return swapped_out_address;
}

void cache::update_lru(uint32_t address)
{
    int index = tag_size + block_size == 32 ? 0 : (address << tag_size) >> (tag_size + block_size);
    int tag = (address >> (set_size + block_size));
    int way = 0;
    for(std::vector<md_entry> &way_vector : metadata) // find the way of the entry
    {
        md_entry &entry = way_vector[index];
        if(entry.tag == tag)
        {
            break;
        }
        way++;
    } 

    int way_index_in_lru = 0;
    for (; way_index_in_lru < ways; way_index_in_lru++) //find the way's index in the LRU
    {
        LRU_entry &lru_entry = LRU_metadata[index][way_index_in_lru];
        if (lru_entry.valid && lru_entry.way == way)
        {
            break;
        }
    }

    for (int i = way_index_in_lru; i > 0; i--) // update the LRU
    {
        LRU_metadata[index][i] = LRU_metadata[index][i - 1];
    }
    LRU_metadata[index][0].way = way;
    LRU_metadata[index][0].valid = true;
}

void cache::remove_from_lru(uint32_t address)
{
    // return;
    int index = tag_size + block_size == 32 ? 0 : (address << tag_size) >> (tag_size + block_size);
    int tag = (address >> (set_size + block_size));
    int way = 0;
    for(std::vector<md_entry> &way_vector : metadata) // find the way of the entry
    {
        md_entry entry = way_vector[index];
        if(entry.valid && entry.tag == tag)
        {
            break;
        }

        way++;
    } 

    int way_index_in_lru = 0;
    for (; way_index_in_lru < ways; way_index_in_lru++) //find the way's index in the LRU
    {
        LRU_entry &lru_entry = LRU_metadata[index][way_index_in_lru];
        if (lru_entry.valid && lru_entry.way == way)
        {
            break;
        }
    }

    for (int i = way_index_in_lru; i < ways - 1; i++) // update the LRU
    {
        LRU_metadata[index][i] = LRU_metadata[index][i + 1];
    }
    LRU_metadata[index][ways - 1].valid = false;
}

// bring to cache a line that is not in the cache
uint32_t cache::load_to_cache(instruction address)
{
    uint32_t swapped_out_address = 0;
    // evict an entry if necessary
    swapped_out_address = evict_entry(address);
    int way = 0; // for DEBUG_PRINT
    for(std::vector<md_entry> &way_vector : metadata)
    {
        int index = tag_size + block_size == 32 ? 0 : (address << tag_size) >> (tag_size + block_size);
        md_entry &entry = way_vector[index];
        if(!entry.valid)
        {
            entry.valid = true;
            if (inst.type == WRITE)
            {
                entry.dirty = true;
            }
            entry.tag = (address >> (set_size + block_size));
            entry.address = address;
            update_lru(address);
            DEBUG_PRINT("load to cache:: address = " << std::hex << address << ", index = " << index << ", entry.tag = " << entry.tag << std::dec << ", way = " << way);       
            return swapped_out_address;
        }
        way++;
    }

    // should never reach here
    assert(false);
    return 0;
}

bool cache::remove_from_cache(uint32_t address)
{
    for(std::vector<md_entry> &way_vector : metadata)
    {
        int index = tag_size + block_size == 32 ? 0 : (address << tag_size) >> (tag_size + block_size);
        int tag = address >> (set_size + block_size);
        md_entry &entry = way_vector[index];
        if(entry.valid && entry.tag == tag)
        {
            remove_from_lru(address);
            entry.valid = false;
            return enrty.dirty;
        }
    }

    return false;
}

int simulator::read(instruction inst)
{
    bool hit;
    DEBUG_PRINT("Checking L1");
    hit = l1.exist(inst);
    l1.total_accesses++;
    if(hit)
    {
        DEBUG_PRINT("L1 hit");
        l1.hit_accesses++;
        l1.update_lru(inst.address);
        return l1.access_time;
    }

    DEBUG_PRINT("Checking L2");
    hit = l2.exist(inst);
    l2.total_accesses++;
    if(hit)
    {
        DEBUG_PRINT("L2 hit");
        l2.hit_accesses++;
        l2.update_lru(inst.address);
        l1.load_to_cache(inst);
        return l2.access_time + l1.access_time;
    }
    DEBUG_PRINT("L2 miss");
    // L2 miss + L1 miss
    if(l2.free_set_entry(inst.address)) //free spot in L2
    {
        DEBUG_PRINT("loading to l2 - free spot in L2");
        l2.load_to_cache(inst);
    } else { // no free spot in L2
        DEBUG_PRINT("loading to l2 - NO free spot in L2");
        uint32_t swapped_out_address = l2.load_to_cache(inst);
        DEBUG_PRINT("remove from l1, address: " << std::hex << swapped_out_address << std::dec);
        bool dirty = l1.remove_from_cache(swapped_out_address);
        if (dirty)
        {
            l2.update_lru(inst.address);
        }
    }
    DEBUG_PRINT("loading to l1");
    l1.load_to_cache(inst);
    DEBUG_PRINT("accessed memory");
    return l2.access_time + l1.access_time + mem_access_time;
}

int simulator::write(instruction inst)
{
    if (write_allocate)
    {
        return read(inst);
    } else {
        bool hit;

        hit = l1.exist(inst);
        l1.total_accesses++;
        if(hit)
        {
            l1.hit_accesses++;
            l1.make_dirty(address);
            l1.update_lru(address);
            return l1.access_time;
        }

        hit = l2.exist(inst);
        l2.total_accesses++;
        if(hit)
        {
            l2.hit_accesses++;
            l2.update_lru(address);
            return l2.access_time + l1.access_time;
        }

        return l2.access_time + l1.access_time + mem_access_time;
    }
}

void simulator::print_instruction(uint32_t address)
{
    

    int way = 0; // for DEBUG_PRINT
    int index = l1.tag_size + l1.block_size == 32 ? 0 : (address << l1.tag_size) >> (l1.tag_size + l1.block_size);
    int tag = (address >> (l1.set_size + l1.block_size));
    DEBUG_PRINT("print_instruction:: l1 data = " << std::hex << ", set = " << index << ", tag = " << tag << std::dec);
    DEBUG_PRINT("L1 LRU:")
    for(int i = 0; i < l1.ways; i++)
    {
        DEBUG_PRINT("way = " << l1.LRU_metadata[index][i].way << ", valid = " << l1.LRU_metadata[index][i].valid);
    }


    index = l2.tag_size + l2.block_size == 32 ? 0 : (address << l2.tag_size) >> (l2.tag_size + l2.block_size);
    tag = (address >> (l2.set_size + l2.block_size));
    DEBUG_PRINT("print_instruction:: l2 data = " << std::hex << ", set = " << index << ", tag = " << tag << std::dec);
    for(int i = 0; i < l2.ways; i++)
    {
        DEBUG_PRINT("way = " << l2.LRU_metadata[index][i].way << ", valid = " << l2.LRU_metadata[index][i].valid);
    }
}

void simulator::run_simulator()
{
    for (instruction &inst : instructions_vec)
    {
        if (inst.type == READ)
        {
            DEBUG_PRINT("Read address: " << std::hex << inst.address << std::dec);
            print_instruction(inst.address);
            total_cycles += this->read(inst);
        } else if (inst.type == WRITE) {
            DEBUG_PRINT("Write address: " << std::hex << inst.address << std::dec);
            print_instruction(inst.address);
            total_cycles += this->write(inst);
        }
    }

    DEBUG_PRINT("Total cycles: " << total_cycles);

    DEBUG_PRINT("l1total_accesses=" << l1.total_accesses << " l1hit_accesses=" << l1.hit_accesses);
    DEBUG_PRINT("l2total_accesses=" << l2.total_accesses << " l2hit_accesses=" << l2.hit_accesses);
    std::cout << std::fixed << std::setprecision(3) <<  "L1miss=" << 1 - ((double)l1.hit_accesses / l1.total_accesses) <<
        " L2miss=" << 1 - ((double)l2.hit_accesses / l2.total_accesses) << " AccTimeAvg=" << ((double)total_cycles / instructions_vec.size()) << std::endl;
}

void simulator::parse_input(int argc, char *argv[])
{
    std::string trace_file = argv[1];
    std::ifstream file(trace_file);
    std::string line;
    while (std::getline(file, line))
    {
        std::istringstream iss(line);
        std::string inst_type;
        uint32_t address;
        iss >> inst_type >> std::hex >> address;
        instruction inst;
        if (inst_type == "r")
        {
            inst.type = READ;
        } else if (inst_type == "w") {
            inst.type = WRITE;
        }
        inst.address = address;
        instructions_vec.push_back(inst);
    }

    std::unordered_map<std::string, int> params;
    params["--mem-cyc"] = 0;
    params["--bsize"] = 0;
    params["--wr-alloc"] = 0;
    params["--l1-size"] = 0;
    params["--l1-assoc"] = 0;
    params["--l1-cyc"] = 0;
    params["--l2-size"] = 0;
    params["--l2-assoc"] = 0;
    params["--l2-cyc"] = 0;

    for (int i = 2; i < argc; i += 2) {
        std::string flag = argv[i];
        if (params.find(flag) != params.end()) {
            params[flag] = std::stoi(argv[i + 1]);
        }
    }

    DEBUG_PRINT("Parsed parameters:");
    for (const auto& param : params) {
        DEBUG_PRINT(param.first << " = " << param.second);
    }

    this->mem_access_time = params["--mem-cyc"];
    this->write_allocate = params["--wr-alloc"];

    this->l1 = cache(params["--l1-cyc"], params["--l1-size"], params["--bsize"], params["--l1-assoc"]);
    this->l2 = cache(params["--l2-cyc"], params["--l2-size"], params["--bsize"], params["--l2-assoc"]);
    
    DEBUG_PRINT("L1 cache:");
    DEBUG_PRINT("Access time: " << l1.access_time);
    DEBUG_PRINT("cache_size: " << l1.cache_size);
    DEBUG_PRINT("Block size: " << l1.block_size);
    DEBUG_PRINT("Ways: " << l1.ways);
    DEBUG_PRINT("Sets: " << l1.set_size);
    DEBUG_PRINT("Tag size: " << l1.tag_size);
    
    DEBUG_PRINT("L2 cache:");
    DEBUG_PRINT("Access time: " << l2.access_time);
    DEBUG_PRINT("cache_size: " << l2.cache_size);
    DEBUG_PRINT("Block size: " << l2.block_size);
    DEBUG_PRINT("Ways: " << l2.ways);
    DEBUG_PRINT("Sets: " << l2.set_size);
    DEBUG_PRINT("Tag size: " << l2.tag_size);

    DEBUG_PRINT("Memory access time: " << mem_access_time);

    DEBUG_PRINT(l2.access_time + l1.access_time + mem_access_time);

    DEBUG_PRINT("Instructions:");
    for (const auto& inst : instructions_vec) {
        DEBUG_PRINT(((inst.type == READ) ? "r" : "w") << " " << std::hex << inst.address << std::dec);
    }
}

int main(int argc, char *argv[])
{
    simulator sim;
    sim.parse_input(argc, argv);
    sim.run_simulator();

    return 0;
}
