/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 *
 * NOTE (Credits):
 * I had issues while developing this circular buffer mainly with handling wrap-around and checking when the
 * buffer becomes full or empty. Bharath Varma’s code and ChatGPT’s explanations helped me fix these logic mistakes and simplify
 * the implementation. 
 *
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */
    if (!buffer) return NULL; // Empty condition: in == out and not full
    
    if ((buffer->out_offs == buffer->in_offs) && (buffer->full == false)) {
        return NULL;// no data available to satisfy any offset
        }
        
    int total_entries = 0; // number of entries to iterate across in write
    int index = buffer->out_offs; // start with the oldest element (read pointer)
    size_t accumulated = 0; // running total of bytes, across entries
    
      if (buffer->full) {		// If full, every slot is valid; otherwise compute the distance from out->in
        total_entries = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    } else if (buffer->in_offs >= buffer->out_offs) {
        total_entries = buffer->in_offs - buffer->out_offs;
    } else {				// Wrapped case- valid region is from out_offs..end plus 0..in_offs-1
        total_entries = AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED - buffer->out_offs + buffer->in_offs;
    }
        for (int i = 0; i < total_entries; i++) { //entries in FIFO order starting at out_offs for total_entries steps
        size_t sz = buffer->entry[index].size;

        if (accumulated + sz > char_offset) { // If the requested char_offset falls within this entry's range
            if (entry_offset_byte_rtn) {
                *entry_offset_byte_rtn = char_offset - accumulated;
            }
            return &buffer->entry[index];	//return the entry pointer that contains the byte
        }
	// Otherwise move past this entry and continue
        accumulated += sz;
        index = (index + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    return NULL;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
void aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    if (!buffer || !add_entry) return;

    // Write the new entry at in_offs
    buffer->entry[buffer->in_offs] = *add_entry;

    // If full, we're overwriting the oldest, advance out_offs
    if (buffer->full) {
        buffer->out_offs = (buffer->out_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }

    // Advance in_offs
    buffer->in_offs = (buffer->in_offs + 1) % AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;

    // If in==out, buffer is now full
    buffer->full = (buffer->in_offs == buffer->out_offs);
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
