export function isAuthenticated(): boolean {
  return !!(localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token'));
}