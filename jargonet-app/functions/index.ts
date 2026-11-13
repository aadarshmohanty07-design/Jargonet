import { createSiteContext, createDatabaseClient, errorResponse } from './_qoder/backend.mjs';
import { PUBLIC_ORIGIN } from './http.mjs';
import { createApplication } from './router.mjs';

// The app owns its accounts and sessions. Platform identity is not used.
const handle = createApplication({
  db: createDatabaseClient(),
  origin: () => Deno.env.get('APP_ORIGIN') || PUBLIC_ORIGIN,
});

Deno.serve(async (request) => {
  let context;
  try {
    context = createSiteContext(request, { forwardApplicationCredentials: true });
    return await handle(context);
  } catch (error) {
    return errorResponse(error, context?.requestId);
  }
});
