import time                                                
import threading

lock = threading.Lock()

def measure_time(log_name):
    def get_timing(f):
        def timed(*args, **kw):
            ts = time.time()
            result = f(*args, **kw)
            te = time.time()
            elapsed_time = te - ts
            #print '%r | %r (%r, %r) %2.2f sec' % \
             #     (threading.current_thread().name, f.__name__, args, kw, te-ts)
            lock.acquire()
            print log_name + ' Elapsed Time: ', elapsed_time
            with open('Timing_' + log_name +'.log', 'a') as tf:
                tf.write(str(elapsed_time) + '\n')
                #tf.write('\n')
            lock.release()
            return result
        return timed
    return get_timing
    
if __name__ == '__main__': get_timing()
