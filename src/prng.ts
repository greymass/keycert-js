// https://github.com/bryc/code/blob/master/jshash/PRNGs.md#sfc32
export default function sfc32(seed: Uint32Array): () => number {
    if (seed.length !== 4) {
        throw new Error('Invalid seed length')
    }
    let a = seed[0]
    let b = seed[1]
    let c = seed[2]
    let d = seed[3]
    return function () {
        a |= 0
        b |= 0
        c |= 0
        d |= 0
        const t = (((a + b) | 0) + d) | 0
        d = (d + 1) | 0
        a = b ^ (b >>> 9)
        b = (c + (c << 3)) | 0
        c = (c << 21) | (c >>> 11)
        c = (c + t) | 0
        return t >>> 0
    }
}
