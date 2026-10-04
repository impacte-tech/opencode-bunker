/**
 * opencode-bunker — plugin entry point.
 *
 * IMPORTANT: opencode treats every named export of a plugin module as a plugin
 * factory and calls it with the PluginInput. Keep this file's only export as
 * `default`; all helpers live in ./core.ts so they are not mistaken for
 * plugins.
 */
export { default } from "./core"
