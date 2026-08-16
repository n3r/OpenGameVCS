/** URLs into the installed, data-only repository-format-v1 artifact. */
export const formatVersion = 1;
export const formatRootUrl = new URL('./', import.meta.url);
export const registriesUrl = new URL('./registries/', import.meta.url);
export const vectorsUrl = new URL('./vectors/', import.meta.url);
