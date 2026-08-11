export async function initializePersonalBusinessContext(
  {
    discover,
    bootstrap,
    validate,
    publish,
    lock,
  },
  { publishContext = true } = {},
) {
  try {
    let context;
    let bootstrapped = false;
    try {
      context = await discover();
    } catch (error) {
      if (error?.status !== 409) throw error;
      context = await bootstrap({ publish: publishContext });
      bootstrapped = true;
    }
    validate(context);
    if (publishContext && !bootstrapped) {
      publish(context.organization_id);
    }
    return context;
  } catch (error) {
    lock("personal_context_unavailable");
    throw error;
  }
}
