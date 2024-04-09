import fs from 'fs'
import dts from 'rollup-plugin-dts'
import typescript from '@rollup/plugin-typescript'
import resolve from '@rollup/plugin-node-resolve'
import commonjs from '@rollup/plugin-commonjs'
import json from '@rollup/plugin-json';
import { terser } from 'rollup-plugin-terser';

import pkg from './package.json'

const name = pkg.name
const license = fs.readFileSync('LICENSE').toString('utf-8').trim()
const banner = `
/**
 * ${name} v${pkg.version}
 * ${pkg.homepage}
 *
 * @license
 * ${license.replace(/\n/g, '\n * ')}
 */
`.trim()

const external = Object.keys(pkg.dependencies)

export default [
    {
        input: 'src/index.ts',
        output: {
            banner,
            file: pkg.main,
            format: 'cjs',
            sourcemap: true,
        },
        plugins: [typescript({target: 'es6'})],
        external,
        onwarn,
    },
    {
        input: 'src/index.ts',
        output: {
            banner,
            file: pkg.module,
            format: 'esm',
            sourcemap: true,
        },
        plugins: [typescript({target: 'es2020'})],
        external,
        onwarn,
    },
    {
        input: 'src/index.ts',
        output: {
            banner,
            name: 'KeycertJs',
            file: pkg.iife,
            format: 'iife',
            globals: {},
            sourcemap: true,
        },
        plugins: [
            json(),
            typescript({ tsconfig: './tsconfig.json' }),
            resolve(), 
            commonjs(),
            terser(),
        ],
        external: [], // All dependencies are bundled
        onwarn,
    },
    {
        input: 'src/index.ts',
        output: {banner, file: pkg.types, format: 'esm'},
        onwarn,
        plugins: [dts()],
    },
]

function onwarn(warning, rollupWarn) {
    if (warning.code === 'CIRCULAR_DEPENDENCY') {
        // unnecessary warning
        return
    }
    if (
        warning.code === 'UNUSED_EXTERNAL_IMPORT' &&
        warning.source === 'tslib' &&
        warning.names[0] === '__read'
    ) {
        // when using ts with importHelpers: true rollup complains about this
        // seems safe to ignore since __read is not actually imported or used anywhere in the resulting bundles
        return
    }
    rollupWarn(warning)
}
