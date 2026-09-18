import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { runInNewContext } from 'node:vm';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const require = createRequire(new URL('../../apps/mobile-app/package.json', import.meta.url));
const ts = require('typescript');

// Run the actual screen effects against a native-bridge double. No account, PIN or network is used.
function load(relative, dependencies, effects) {
  const source = process.argv.includes('--baseline')
    ? execFileSync('git', ['show', `HEAD:apps/mobile-app/${relative}`], { cwd: fileURLToPath(new URL('../..', import.meta.url)), encoding: 'utf8' })
    : readFileSync(new URL(`../../apps/mobile-app/${relative}`, import.meta.url), 'utf8');
  const code = ts.transpileModule(source, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true },
  }).outputText;
  const exports = {};
  const hooks = {
    useState: initial => [initial, () => {}],
    useRef: initial => ({ current: initial }),
    useCallback: fn => fn,
    useEffect: effect => effects.push(effect),
  };
  const context = {
    exports,
    require(name) {
      if (name === 'react') return hooks;
      if (name === 'react/jsx-runtime') return { jsx: () => null, jsxs: () => null };
      if (name in dependencies) return dependencies[name];
      if (name.startsWith('@/components/')) return {};
      throw new Error(`Unexpected test dependency: ${name}`);
    },
    console: { log() {}, error() {} },
    setTimeout: fn => { queueMicrotask(fn); return 1; },
    clearTimeout() {},
  };
  runInNewContext(code, context, { filename: relative });
  return exports;
}

for (const screen of ['initialize', 'reinitialize']) {
  for (const scenario of ['offline', 'pending-sync', 'cancel', 'migration']) {
    test(`${screen}: PIN ${scenario}`, async () => {
      const events = [];
      let unlocked = false;
      let available = false;
      const native = {
        hasEncryptedDatabase: async () => true,
        isVaultUnlocked: async () => unlocked,
        isPinEnabled: async () => true,
        async showPinUnlock() {
          events.push('pin');
          if (scenario === 'cancel') throw new Error('User cancelled');
          unlocked = true;
        },
      };
      const db = {
        hasPendingMigrations: async () => scenario === 'migration',
        unlockVault: async () => { throw new Error('PIN must not invoke biometric/password unlock'); },
        setDatabaseAvailable: () => { available = true; events.push('available'); },
        refreshSyncState: async () => {},
        setIsOffline: async () => {},
      };
      const router = { replace: route => events.push(route) };
      const dependencies = {
        '@/specs/NativeVaultManager': native,
        'expo-router': { router, useRouter: () => router },
        'react-i18next': { useTranslation: () => ({ t: key => key }) },
        'react-native': { StyleSheet: { create: value => value }, Platform: { OS: 'android' } },
        '@/hooks/useColorScheme': { useColors: () => ({ textMuted: '#666' }) },
        '@/context/AppContext': { useApp: () => ({ initializeAuth: async () => ({ isLoggedIn: true, enabledAuthMethods: ['password'] }) }) },
        '@/context/DbContext': { useDb: () => db },
        '@/context/NavigationContext': { useNavigation: () => ({ navigateAfterUnlock: () => events.push(available ? 'tabs' : 'stale-database') }) },
        '@/hooks/useVaultSync': { useVaultSync: () => ({ syncVault: async options => {
          events.push('sync');
          if (scenario === 'offline') { await options.onOffline(); return true; }
          return new Promise(() => {});
        } }) },
      };
      dependencies['@/utils/VaultUnlockHelper'] = load('utils/VaultUnlockHelper.ts', dependencies, []);
      const effects = [];
      load(`app/${screen}.tsx`, dependencies, effects).default();
      effects.forEach(effect => effect());
      for (let attempt = 0; attempt < 30; attempt++) await new Promise(resolve => setImmediate(resolve));
      assert.equal(events.filter(event => event === 'pin').length, 1);
      if (scenario === 'cancel' || scenario === 'migration') {
        assert.ok(events.includes(scenario === 'cancel' ? '/unlock' : '/upgrade'));
        assert.equal(available, false);
        assert.equal(events.includes('sync'), false);
      } else {
        assert.ok(events.includes('tabs'), JSON.stringify(events));
        assert.ok(events.indexOf('available') < events.indexOf('tabs'));
        assert.equal(events.includes('/login'), false);
        assert.equal(events.includes('/unlock'), false);
      }
    });
  }
}

for (const loggedIn of [true, false]) {
  test(`tab guard: ${loggedIn ? 'locked local vault' : 'signed out'}`, async () => {
    const routes = [];
    const effects = [];
    const dependencies = {
      'expo-router': { router: { replace: route => routes.push(route) } },
      'react-i18next': { useTranslation: () => ({ t: key => key }) },
      'react-native': {},
      '@/utils/EventEmitter': {},
      '@/hooks/useColorScheme': { useColors: () => ({}) },
      '@/context/AppContext': { useApp: () => ({ isInitialized: true, isLoggedIn: loggedIn }) },
      '@/context/DbContext': { useDb: () => ({ dbInitialized: true, dbAvailable: false }) },
    };
    load('app/(tabs)/_layout.tsx', dependencies, effects).default();
    effects.forEach(effect => effect());
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(routes, [loggedIn ? '/reinitialize' : '/login']);
  });
}
