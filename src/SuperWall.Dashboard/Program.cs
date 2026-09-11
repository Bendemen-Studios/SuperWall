// PATCH: device profile changes must survive agent sync.
// The profile endpoint writes the selected profile and rebuilds that device's policy immediately.
// The agent receives the effective policy on its next sync; profile is no longer inferred from an old policy snapshot.
