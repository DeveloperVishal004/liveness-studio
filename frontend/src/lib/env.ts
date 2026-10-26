/**
 * True only in the hosted, demo-only build (`npm run build:demo`). That build has no camera, no engine and no /api calls:
 * it can only play the scripted, clearly labelled simulation.
 */
export const DEMO_ONLY: boolean = import.meta.env.VITE_DEMO_ONLY === 'true'
