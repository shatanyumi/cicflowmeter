#ifndef _ID_GENERATOR_H_
#define _ID_GENERATOR_H_

#include <cstdint>
#include <atomic>

class IDGenerator
{
private:
    int id_counter;

public:
    IDGenerator()
    {
        id_counter = 0;
    }
    void reset_id_counter()
    {
        id_counter = 0;
    }

    void increment_id_counter()
    {
        id_counter++;
    }

    void set_id_counter(uint64_t id)
    {
        id_counter = id;
    }

    uint64_t next_id()
    {
        increment_id_counter();
        return id_counter;
    }
};
#endif // _ID_GENERATOR_H_
