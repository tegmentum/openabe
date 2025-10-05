/**
 * OpenABE Worker Pool
 * Manages a pool of Web Workers for parallel cryptographic operations
 */

class OpenABEWorkerPool {
    constructor(options = {}) {
        this.workerCount = options.workerCount || navigator.hardwareConcurrency || 4;
        this.workerScript = options.workerScript || 'openabe-worker.js';
        this.workers = [];
        this.taskQueue = [];
        this.activeJobs = new Map();
        this.nextContextId = 0;

        this._initializeWorkers();
    }

    /**
     * Initialize worker pool
     * @private
     */
    _initializeWorkers() {
        for (let i = 0; i < this.workerCount; i++) {
            const worker = new Worker(this.workerScript);

            worker.onmessage = (e) => this._handleResult(e);
            worker.onerror = (e) => this._handleError(e);

            this.workers.push({
                id: i,
                worker,
                busy: false,
                contextIds: new Set()
            });
        }
    }

    /**
     * Create a new ABE context
     */
    async createContext(scheme, options = {}) {
        const contextId = `ctx_${this.nextContextId++}`;

        // Initialize context on all workers for load balancing
        const promises = this.workers.map(w =>
            this._enqueue({
                type: 'init-context',
                contextId,
                scheme,
                curve: options.curve
            }, w.id)
        );

        await Promise.all(promises);

        return new WorkerPoolContext(this, contextId, scheme);
    }

    /**
     * Enqueue a task
     * @private
     */
    _enqueue(task, preferredWorkerId = null) {
        return new Promise((resolve, reject) => {
            const jobId = crypto.randomUUID();

            this.activeJobs.set(jobId, { resolve, reject });

            this.taskQueue.push({
                ...task,
                jobId,
                preferredWorkerId
            });

            this._scheduleNext();
        });
    }

    /**
     * Schedule next task
     * @private
     */
    _scheduleNext() {
        if (this.taskQueue.length === 0) return;

        // Find free worker
        let worker;
        const task = this.taskQueue[0];

        if (task.preferredWorkerId !== null) {
            worker = this.workers.find(
                w => w.id === task.preferredWorkerId && !w.busy
            );
        }

        if (!worker) {
            worker = this.workers.find(w => !w.busy);
        }

        if (!worker) return; // All workers busy

        // Remove task from queue
        this.taskQueue.shift();

        // Mark worker as busy
        worker.busy = true;

        // Send task to worker
        worker.worker.postMessage(task);
    }

    /**
     * Handle result from worker
     * @private
     */
    _handleResult(event) {
        const { jobId, result, error } = event.data;
        const job = this.activeJobs.get(jobId);

        if (!job) {
            console.error('Unknown job ID:', jobId);
            return;
        }

        if (error) {
            job.reject(new Error(error));
        } else {
            job.resolve(result);
        }

        this.activeJobs.delete(jobId);

        // Mark worker as free
        const worker = this.workers.find(w => w.worker === event.target);
        if (worker) {
            worker.busy = false;
            this._scheduleNext();
        }
    }

    /**
     * Handle worker error
     * @private
     */
    _handleError(event) {
        console.error('Worker error:', event);

        // Find and restart failed worker
        const workerIndex = this.workers.findIndex(w => w.worker === event.target);
        if (workerIndex >= 0) {
            const oldWorker = this.workers[workerIndex];
            oldWorker.worker.terminate();

            // Create new worker
            const newWorker = new Worker(this.workerScript);
            newWorker.onmessage = (e) => this._handleResult(e);
            newWorker.onerror = (e) => this._handleError(e);

            this.workers[workerIndex] = {
                id: oldWorker.id,
                worker: newWorker,
                busy: false,
                contextIds: new Set()
            };
        }
    }

    /**
     * Batch key generation
     */
    async batchKeygen(contextId, tasks) {
        const promises = tasks.map(task =>
            this._enqueue({
                type: 'keygen',
                contextId,
                ...task
            })
        );

        return Promise.all(promises);
    }

    /**
     * Batch encryption
     */
    async batchEncrypt(contextId, tasks) {
        const promises = tasks.map(task =>
            this._enqueue({
                type: 'encrypt',
                contextId,
                ...task
            })
        );

        return Promise.all(promises);
    }

    /**
     * Batch decryption
     */
    async batchDecrypt(contextId, tasks) {
        const promises = tasks.map(task =>
            this._enqueue({
                type: 'decrypt',
                contextId,
                ...task
            })
        );

        return Promise.all(promises);
    }

    /**
     * Get pool statistics
     */
    getStats() {
        return {
            totalWorkers: this.workers.length,
            busyWorkers: this.workers.filter(w => w.busy).length,
            queueLength: this.taskQueue.length,
            activeJobs: this.activeJobs.size
        };
    }

    /**
     * Terminate all workers
     */
    terminate() {
        for (const worker of this.workers) {
            worker.worker.terminate();
        }

        this.workers = [];
        this.taskQueue = [];
        this.activeJobs.clear();
    }
}

/**
 * Context wrapper for worker pool
 */
class WorkerPoolContext {
    constructor(pool, contextId, scheme) {
        this.pool = pool;
        this.contextId = contextId;
        this.scheme = scheme;
    }

    async generateParams() {
        return this.pool._enqueue({
            type: 'generate-params',
            contextId: this.contextId
        });
    }

    async keygen(attributes, keyId, authId = null, gid = null) {
        return this.pool._enqueue({
            type: 'keygen',
            contextId: this.contextId,
            attributes,
            keyId,
            authId,
            gid
        });
    }

    async encrypt(policy, plaintext) {
        const result = await this.pool._enqueue({
            type: 'encrypt',
            contextId: this.contextId,
            policy,
            plaintext
        });

        return new Uint8Array(result.ciphertext);
    }

    async decrypt(keyId, ciphertext) {
        const result = await this.pool._enqueue({
            type: 'decrypt',
            contextId: this.contextId,
            keyId,
            ciphertext: Array.from(ciphertext)
        });

        if (!result.success) {
            return null;
        }

        return new Uint8Array(result.plaintext);
    }

    async exportPublicParams() {
        const result = await this.pool._enqueue({
            type: 'export-params',
            contextId: this.contextId,
            type: 'public'
        });

        return new Uint8Array(result.params);
    }

    async importPublicParams(params, authId = null) {
        return this.pool._enqueue({
            type: 'import-params',
            contextId: this.contextId,
            type: 'public',
            params: Array.from(params),
            authId
        });
    }

    async exportSecretParams() {
        const result = await this.pool._enqueue({
            type: 'export-params',
            contextId: this.contextId,
            type: 'secret'
        });

        return new Uint8Array(result.params);
    }

    async importSecretParams(params, authId = null) {
        return this.pool._enqueue({
            type: 'import-params',
            contextId: this.contextId,
            type: 'secret',
            params: Array.from(params),
            authId
        });
    }

    /**
     * Batch key generation
     */
    async batchKeygen(tasks) {
        return this.pool.batchKeygen(this.contextId, tasks);
    }

    /**
     * Batch encryption
     */
    async batchEncrypt(tasks) {
        const results = await this.pool.batchEncrypt(this.contextId, tasks);
        return results.map(r => new Uint8Array(r.ciphertext));
    }

    /**
     * Batch decryption
     */
    async batchDecrypt(tasks) {
        const results = await this.pool.batchDecrypt(this.contextId, tasks);
        return results.map(r =>
            r.success ? new Uint8Array(r.plaintext) : null
        );
    }
}

// Export for use in modules or browser
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { OpenABEWorkerPool, WorkerPoolContext };
}
