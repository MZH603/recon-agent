// Resolve the frontend dependency from its own package, even though tests live elsewhere.
import {createRequire} from 'node:module';
import {pathToFileURL} from 'node:url';

const require = createRequire(new URL('../../cli/tui/package.json', import.meta.url));
export const {visibleWidth} = await import(pathToFileURL(require.resolve('@earendil-works/pi-tui')).href);
