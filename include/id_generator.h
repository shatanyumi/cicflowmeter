#ifndef _ID_GENERATOR_H_
#define _ID_GENERATOR_H_

#include <cstdint>
#include <atomic>

static std::atomic<uint64_t> id_counter = 0;

void reset_id_counter()
{
    id_counter.store(0);
}

void increment_id_counter()
{
    id_counter.fetch_add(1);
}

void set_id_counter(uint64_t id)
{
    id_counter.store(id);
}

uint64_t next_id()
{
    return id_counter.fetch_add(1) + 1; // Ensure it starts from 1 instead of 0
}

#endif // _ID_GENERATOR_H_
