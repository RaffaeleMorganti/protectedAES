/** 
 * Countermeasures are enabled by default
 * This is just for library testing
 **/


// enables masking countermeasure
#define MASKING

// enables hiding countermeasure
#define HIDING

// getMasking show mask and getHiding return number of interrupts
//#define DEBUG

/** TIMINGS (microseconds) PER COUNTERMEASURES
 * AES | MASKING | HIDING | MEAN  | STDDEV
 * 128 | NO      | NO     | ~750  | <10
 * 128 | NO      | YES    | ~2090 | ~490 
 * 128 | YES     | NO     | ~2080 | <10
 * 128 | YES     | YES    | ~4540 | ~430
 * 192 | NO      | NO     | ~870  | <10
 * 192 | NO      | YES    | ~2410 | ~520
 * 192 | YES     | NO     | ~2310 | ~10
 * 192 | YES     | YES    | ~5030 | ~460
 * 256 | NO      | NO     | ~990  | <10
 * 256 | NO      | YES    | ~2730 | ~550
 * 256 | YES     | NO     | ~2550 | ~10
 * 256 | YES     | YES    | ~5520 | ~470
 **/
