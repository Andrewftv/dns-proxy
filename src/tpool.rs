use std::{
//    time::Duration,
    sync::atomic::{AtomicBool, AtomicU64, Ordering },
    sync::{mpsc, Arc, Mutex},
    thread,
};
use crate::log_debug;
use crate::log_info;

#[derive(Clone)]
pub struct TPoolStat {
    workers_num: usize,
    busy: Vec<bool>,
    jobs_complete: Vec<u64> 
}

impl TPoolStat {
    pub fn new(workers_num: usize) -> TPoolStat {
        let busy: Vec<bool> = vec![false; workers_num];
        let jobs_complete: Vec<u64> = vec![0; workers_num];

        TPoolStat { 
            workers_num,
            busy,
            jobs_complete
         }
    }

    pub fn get_workers(&self) -> usize {
        return self.workers_num;
    }

    pub fn get_busy(&self, id:usize) -> bool {
        if id >= self.workers_num {
            return false;
        }
        return self.busy[id];
    }

    pub fn get_jobs(&self, id: usize) -> u64 {
        if id >= self.workers_num {
            return 0;
        }
        return self.jobs_complete[id];
    }
}

pub struct ThreadPool {
    workers: Vec<Worker>,
    sender: Option<mpsc::Sender<Job>>,
}

type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    pub fn new(size: usize) -> ThreadPool {
        log_info!("Create thread pool. size: {}\n", size);

        let (sender, receiver) = mpsc::channel();
        let receiver = Arc::new(Mutex::new(receiver));
        let mut workers = Vec::with_capacity(size);

        for id in 0..size {
            workers.push(Worker::new(id));
            workers[id].start(id, Arc::clone(&receiver));
        }

        ThreadPool {
            workers,
            sender: Some(sender),
        }
    }

    pub fn get_stat(&self) -> TPoolStat {
        let workers_num = self.workers.capacity();
        let mut busy: Vec<bool> = Vec::with_capacity(workers_num);
        let mut jobs_complete: Vec<u64> = Vec::with_capacity(workers_num);
        busy.resize(workers_num, false);
        jobs_complete.resize(workers_num, 0);
        for id in 0..workers_num {
            busy[id] = self.workers[id].is_busy();
            jobs_complete[id] = self.workers[id].jobs_count();
        }

        TPoolStat {
            workers_num,
            busy,
            jobs_complete
        }
    }

//    pub fn log_status(&self) {
//        let size = self.workers.capacity();
//        log_debug!("--------------------------------------------------\n");
//        for id in 0..size {
//            log_debug!("Worker ID: {} is busy: {}\tjobs completed: {}\n", 
//                id, self.workers[id].is_busy(), self.workers[id].jobs_count());
//        }
//        log_debug!("--------------------------------------------------\n");
//    }

    pub fn execute<F>(&self, f: F)
    where
        F: FnOnce() + Send + 'static,
    {
        let job = Box::new(f);

        self.sender.as_ref().unwrap().send(job).unwrap();
    }
}

impl Drop for ThreadPool {
    fn drop(&mut self) {
        log_debug!("Call drop of thread pool\n");
        drop(self.sender.take());

        for worker in &mut self.workers {
            log_debug!("Shutting down worker {}\n", worker.id);

            if let Some(thread) = worker.thread.take() {
                thread.join().unwrap();
            }
        }
    }
}

struct Worker {
    id: usize,
    thread: Option<thread::JoinHandle<()>>,
    busy: Arc<AtomicBool>,
    count: Arc<AtomicU64>
}

impl Worker {
    fn new(id: usize) -> Worker {
        let busy = Arc::new(AtomicBool::new(false));
        let count = Arc::new(AtomicU64::new(0));
        Worker {
            id,
            thread: None,
            busy,
            count
        }
    }

    pub fn is_busy(&self) -> bool {
        return self.busy.load(Ordering::Relaxed);
    }

    pub fn jobs_count(&self) -> u64 {
        return self.count.load(Ordering::Relaxed);
    }

    pub fn start(&mut self, id: usize, receiver: Arc<Mutex<mpsc::Receiver<Job>>>) -> bool {
        let mbusy = self.busy.clone();
        let mcount = self.count.clone();

        let thread = thread::spawn(move || loop {
            let message = receiver.lock().unwrap().recv();

            match message {
                Ok(job) => {
                    //log_debug!("Worker {} got a job; executing\n", id);
                    mbusy.store(true, Ordering::Relaxed);
                    job();
                    mcount.fetch_add(1, Ordering::Relaxed);
                    mbusy.store(false, Ordering::Relaxed);
                }
                Err(_) => {
                    log_info!("Worker {} disconnected; shutting down\n", id);
                    break;
                }
            }
        });

        self.thread = Some(thread);

        return true;
    }
}
