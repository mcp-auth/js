import { condString } from '@silverhand/essentials';

/**
 * A simple implementation for generating WWW-Authenticate response headers
 * specifically for Bearer authentication scheme, based on RFC 6750.
 */
export class BearerWWWAuthenticateHeader {
  private readonly authParams = new Map<string, string>();

  /**
   * Sets an authentication parameter.
   * If the value is undefined or empty string, the parameter will be ignored.
   *
   * @param param The parameter name
   * @param value The parameter value, if undefined the parameter will not be set
   */
  setParameterIfValueExists(param: string, value?: string) {
    if (value) {
      this.authParams.set(param, value);
    }
    return this;
  }

  toString() {
    const params = Array.from(this.authParams.entries())
      .map(([key, value]) => `${key}="${value}"`)
      .join(', ');

    return condString(params && `Bearer ${params}`);
  }

  get headerName() {
    return 'WWW-Authenticate';
  }
}
