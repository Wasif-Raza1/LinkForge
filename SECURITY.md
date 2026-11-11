# LinkForge — Security Architecture & Privilege Enforcement Report

## 1. Executive Summary

This report documents the multi-layer cybersecurity architecture implemented in LinkForge to enforce strict Role-Based Access Control (RBAC), protect proprietary publisher inventory, and mathematically guarantee that normal users can never escalate privileges or grant themselves administrative rights.

---

## 2. The Threat Model & Countermeasures

### Threat 1: User Alters Role in Client-Side Storage or DevTools
- **Attack Vector**: An attacker opens Browser Developer Tools, edits `localStorage.getItem("linkforge_currentUser")`, and sets `"role": "super_admin"`.
- **Enforced Defense**:
  1. Client-side state is strictly visual. All actual data writes, listing CRUD, order updates, and role alterations are validated server-side and through PostgreSQL Row Level Security (RLS).
  2. In PostgreSQL, the `profiles` table has an RLS policy:
     ```sql
     CREATE POLICY "Users can update own personal info"
       ON public.profiles FOR UPDATE
       TO authenticated
       USING (auth.uid() = id)
       WITH CHECK (auth.uid() = id AND role = (SELECT role FROM public.profiles WHERE id = auth.uid()));
     ```
     Even if an authenticated user transmits an `UPDATE profiles SET role = 'admin'` SQL query or API request directly to Supabase, PostgreSQL evaluates the `WITH CHECK` expression against the persisted database record and immediately rejects the operation with a security violation.

---

### Threat 2: Attacker Submits a Custom Role Field During Public Registration
- **Attack Vector**: An attacker crafts an automated POST request to the registration endpoint containing `{"email": "attacker@evil.com", "role": "super_admin"}`.
- **Enforced Defense**:
  1. The registration handler explicitly disregards any input role field and enforces `role: 'user'`.
  2. Database-level Security Definer trigger (`public.handle_new_user()`):
     ```sql
     IF NEW.email = 'admin@example.com' THEN
       v_role := 'super_admin';
     ELSE
       v_role := 'user';
     END IF;
     ```
     The trigger intercepts user insertion in `auth.users` and forces `v_role := 'user'`. The only email address permitted to bootstrap as Super Admin is `admin@example.com`.

---

### Threat 3: Secondary Administrator Attempts to Demote or Lock Out the Super Admin
- **Attack Vector**: A secondary admin tries to delete, demote, or suspend the primary Super Admin account to hijack the platform.
- **Enforced Defense**:
  Database-level security trigger `trg_protect_profile_roles` on `public.profiles`:
  ```sql
  IF OLD.email = 'admin@example.com' AND (NEW.role <> 'super_admin' OR NEW.is_suspended = TRUE) THEN
    RAISE EXCEPTION 'Cannot demote or suspend the primary Super Admin.';
  END IF;
  ```
  PostgreSQL aborts the transaction before any write occurs. The primary Super Admin account is cryptographically and procedurally immutable.

---

### Threat 4: Secondary Administrator Tries to Create Another Super Admin
- **Attack Vector**: A secondary admin attempts to elevate another account to `super_admin`.
- **Enforced Defense**:
  Database-level check in `enforce_profile_role_security()`:
  ```sql
  IF NEW.role = 'super_admin' AND OLD.email <> 'admin@example.com' THEN
    RAISE EXCEPTION 'Access Denied: Cannot create additional Super Admins.';
  END IF;
  ```
  Only the original Super Admin (`admin@example.com`) can manage administrator roles.

---

### Threat 5: Unauthenticated Scraper Harvesting Marketplace Listings
- **Attack Vector**: Competitors or scrapers crawl the marketplace to steal domain URLs and publisher pricing.
- **Enforced Defense**:
  1. Before registration / login: Database delivers masked preview strings (`tech***.com`) and conceals editorial contact instructions.
  2. Full verified domains and active links are unlocked ONLY after authentication.
  3. Ordering drawer requires valid authenticated session.

---

### Threat 6: Cross-Account Order Inspection (IDOR)
- **Attack Vector**: User A attempts to view User B's order details by navigating to `/orders/ORD-9021`.
- **Enforced Defense**:
  Row Level Security on `public.orders`:
  ```sql
  CREATE POLICY "Users can view own orders"
    ON public.orders FOR SELECT
    TO authenticated
    USING (auth.uid() = user_id);
  ```
  PostgreSQL silently filters query results to include only rows where `user_id = auth.uid()`. Normal users are mathematically incapable of reading another customer's orders.

---

## 3. Security Audit Logging

All administrative events are recorded to an append-only audit ledger (`public.admin_activity_logs`):
- `ADMIN_LOGIN`
- `SYSTEM_BOOTSTRAP_SUPER_ADMIN`
- `PROMOTE_TO_ADMIN`
- `REVOKE_ADMIN`
- `SUSPEND_USER`
- `REACTIVATE_USER`
- `CREATE_LISTING`
- `UPDATE_LISTING`
- `DELETE_LISTING`
- `UPDATE_ORDER_STATUS`
- `GOOGLE_SHEETS_SYNC`

Normal users have no read or write permissions to `admin_activity_logs`. Secondary administrators cannot delete or modify their own audit history.
