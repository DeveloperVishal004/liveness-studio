/**
 * True in the hosted build (`npm run build:demo`). That build has no local engine and makes no /api calls: it offers the
 * in-browser models (everything runs on the visitor's device) and the scripted, clearly labelled demo.
 */
export const HOSTED: boolean = import.meta.env.VITE_HOSTED === 'true'
