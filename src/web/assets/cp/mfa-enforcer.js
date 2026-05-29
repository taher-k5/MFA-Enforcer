(function () {
    'use strict';

    const config = window.MfaEnforcerConfig;
    if (!config) {
        return;
    }
    // Run the interceptors when EITHER:
    //   (a) content-type protection is active (applies + at least one protectedAction), OR
    //   (b) the current user is enrolled in MFA (to protect plugin settings saves).
    // Without (b) the settings-save modal would never appear when protectedActions is empty.
    const hasContentProtection = config.applies && config.protectedActions && Object.keys(config.protectedActions).length > 0;
    if (!hasContentProtection && !config.userEnrolled) {
        return;
    }

    // Always read a fresh copy of the config so that Craft CP PJAX navigation
    // (which replaces window.MfaEnforcerConfig with a new object) is reflected
    // in every interception check. Falls back to the snapshot captured above
    // in case the global is somehow cleared.
    function getConfig() {
        return window.MfaEnforcerConfig || config || {};
    }

    const TOKEN_HEADER = 'X-Mfa-Enforcer-Token';
    const MFA_TOKEN_TTL_MS = 3000;

    let recentMfaToken = null;
    let recentMfaExpires = 0;

    function storeRecentMfaToken(token) {
        recentMfaToken = token;
        recentMfaExpires = Date.now() + MFA_TOKEN_TTL_MS;
    }

    function getRecentMfaToken() {
        if (!recentMfaToken) {
            return null;
        }

        if (Date.now() > recentMfaExpires) {
            recentMfaToken = null;
            recentMfaExpires = 0;
            return null;
        }

        return recentMfaToken;
    }

    // Upload batching state.
    // Reuses the global MFA token cache (3s TTL) so uploads behave like all
    // other protected actions, while still allowing multi-file uploads to wait
    // for one modal confirmation.
    let uploadModalPending = false;
    let pendingUploadCallbacks = [];

    // Called after MFA succeeds or is cancelled for an upload.
    // Releases all queued upload XHRs with the same token.
    function notifyUploadCallbacks(token) {
        const cbs = pendingUploadCallbacks.slice();

        pendingUploadCallbacks = [];
        uploadModalPending = false;

        cbs.forEach(function (cb) {
            try {
                cb(token);
            } catch (_) {}
        });
    }

    // Universal "write-shaped action" detection. Any Craft CP request to
    // /actions/<controller>/<...keyword> where the keyword indicates a mutating
    // operation is a candidate for MFA. Server-side guards decide whether the
    // particular resource (section / volume / etc.) is actually protected and
    // whether the supplied token was required.
    const WRITE_KEYWORD_RE = /(^|\/)actions\/[^?#]*?(save|create|delete|install|uninstall|apply|upload|replace|activate|suspend|unsuspend|config-sync|rebuild|retry|release)\b/i;
    // Known write-shaped routes that are *not* user-initiated content writes
    // and therefore should never prompt. Drafts auto-save / discard / revert
    // happen constantly in the background and must be silently allowed —
    // MFA fires only on the explicit "publish" call (apply-draft).
    const WRITE_DENYLIST_RE = /(recent-activity|get-elevated-session-timeout|preview-file|get-cp-alerts|api-headers|cache-updates|check-for-updates|render-element|card-html|get-elements|search\b|process-api-response-headers|shun-cp-alert|asset-html|element-html|countdown|chart|notifications|sessions|stream|save-draft|delete-draft|discard-draft|discard-changes|save-revision|merge-canonical-changes|revert-content|create-draft)/i;

    function isWriteUrl(url) {
        if (typeof url !== 'string' || !url) return false;
        let decoded;
        try { decoded = decodeURIComponent(url); } catch (_) { decoded = url; }
        const isWrite = WRITE_KEYWORD_RE.test(decoded);
        const isDenied = WRITE_DENYLIST_RE.test(decoded);
        if (!isWrite) {
            // Special-case: element-indexes perform-action can carry an elementAction
            // that performs deletes (e.g. craft\elements\actions\Delete). Treat
            // the endpoint as write-shaped — further checks will be performed on
            // the request body when possible.
            if (/element-indexes\/perform-action/i.test(decoded)) return true;
            return false;
        }
        if (isDenied) return false;
        return true;
    }

    function isWriteFormAction(value) {
        if (!value) return false;
        return isWriteUrl('/actions/' + value);
    }

    function bodyMentionsDraft(body) {

        if (!body) {return false;}

        try {
            if (typeof FormData !== 'undefined' && body instanceof FormData) {
                return (
                    body.has('draftId') || body.has('provisional')
                );
            }

            if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
                return (
                    body.has('draftId') || body.has('provisional')
                );
            }

            if (typeof body === 'string') {
                return /(?:^|[&?])(draftId|provisional)=|"(?:draftId|provisional)"/i.test(body);
            }

        } catch (_) {}
        return false;
    }

    function formMentionsDraft(form) {
        const draft = form.querySelector('input[name="draftId"], input[name="provisional"]');

        return !!(draft && draft.value);
    }

    function isDeleteWithDraftId(url, body) {

        let decoded;

        try {
            decoded = decodeURIComponent(url || '');
        } catch (_) {
            decoded = url || '';
        }

        if (!/elements\/delete\b/i.test(decoded)) {
            return false;
        }
        return bodyMentionsDraft(body);
    }

    // ---- Settings-aware protection check ----
    // 'source' is the element-index source key (e.g. 'section:UUID' / 'group:UUID')
    // sent in every element-indexes/perform-action payload.
    const PARAM_KEYS = ['sectionId', 'groupId', 'setId', 'globalSetId', 'entryId', 'sourceId', 'elementAction', 'elementType', 'draftId', 'canonicalId', 'provisional', 'source', 'folderId'];

    function extractBodyParams(body) {
        const params = {};
        if (!body) return params;
        function assign(k, v) { if (v !== null && v !== undefined && v !== '') params[k] = String(v); }
        if (body instanceof FormData || body instanceof URLSearchParams) {
            PARAM_KEYS.forEach(function (k) { assign(k, body.get(k)); });
        } else if (typeof body === 'string') {
            try {
                const sp = new URLSearchParams(body);
                PARAM_KEYS.forEach(function (k) { assign(k, sp.get(k)); });
            } catch (_) {}
            if (!Object.keys(params).length) {
                try {
                    const json = JSON.parse(body);
                    PARAM_KEYS.forEach(function (k) { assign(k, json[k]); });
                } catch (_) {}
            }
        }
        return params;
    }

    function extractFormParams(form) {
        const params = {};
        if (!form) return params;
        PARAM_KEYS.forEach(function (k) {
            const el = form.querySelector('input[name="' + k + '"], select[name="' + k + '"]');
            if (el && el.value) params[k] = el.value;
        });
        return params;
    }

    function isActionProtectedBySettings(url, params) {
        try {
            const actions = getConfig().protectedActions;
            if (!actions) return false;
            let u;
            try { u = decodeURIComponent(url).toLowerCase(); } catch (_) { u = (url || '').toLowerCase(); }

            // MFA Enforcer plugin settings save routes.
            // Only show the modal when the user is actively enrolled in MFA;
            // un-enrolled users can change settings without a challenge.
            if (/\/mfa-enforcer\/settings\/save-general\b/.test(u) ||
                /\/mfa-enforcer\/settings\/save-protected-actions\b/.test(u)) {
                return !!getConfig().userEnrolled;
            }

            // Utilities: Project Config actions
            if (/project-config\/rebuild\b/.test(u)) {
                return !!actions['utilities.projectConfig.rebuild'];
            }
            if (/project-config\/download\b/.test(u)) {
                return !!actions['utilities.projectConfig.download'];
            }
            if (/\/config-sync\b/.test(u)) {
                // Protect the explicit "reapply everything" flow when force=1
                const f = params && params.force;
                if (f === '1' || f === 1 || f === true) return !!actions['utilities.projectConfig.reapply'];
            }

            // Utilities: Queue Manager actions
            if (/queue\/retry(-all)?\b/.test(u)) {
                return !!actions['utilities.queueManager.retry'];
            }
            if (/queue\/release(-all)?\b/.test(u)) {
                return !!actions['utilities.queueManager.release'];
            }

            // Utilities: Find and Replace
            if (/find-and-replace-perform-action\b/.test(u)) {
                return !!actions['utilities.findAndReplace'];
            }

            // Resolve the resource id for the current operation. Priority:
            //   1. explicit id in the request body (sectionId / groupId / setId / globalSetId)
            //   2. the resource context the server detected from the CP URL (config.currentResourceContext)
            //
            // We deliberately do NOT fall back to "match any of this resource type" — that
            // is what made protecting one section appear to apply to every section.
            function resolveResourceId(resourceType) {
                const ctx = getConfig().currentResourceContext;
                switch (resourceType) {
                    case 'entry':
                        if (params.sectionId) return parseInt(params.sectionId, 10);
                        if (ctx && ctx.type === 'entry' && ctx.id) return parseInt(ctx.id, 10);
                        return null;
                    case 'asset':
                        // Priority: explicit volumeId param, then sourceKeyMap ('volume:{uid}'),
                        // then folderVolumeMap (resolves folderId from assets/upload body),
                        // then currentResourceContext (set when page URL is /assets/{handle})
                        if (params.volumeId) return parseInt(params.volumeId, 10);
                        if (params.source) {
                            const skm = getConfig().sourceKeyMap || {};
                            const sm = skm[params.source];
                            if (sm && sm.type === 'asset' && sm.id) return sm.id;
                        }
                        if (params.folderId) {
                            const fvm = getConfig().folderVolumeMap || {};
                            const vid = fvm[String(params.folderId)];
                            if (vid) return vid;
                        }
                        if (ctx && ctx.type === 'asset' && ctx.id) return parseInt(ctx.id, 10);
                        return null;
                    case 'category':
                        if (params.groupId) return parseInt(params.groupId, 10);
                        if (ctx && ctx.type === 'category' && ctx.id) return parseInt(ctx.id, 10);
                        return null;
                    case 'globalSet':
                        if (params.setId) return parseInt(params.setId, 10);
                        if (params.globalSetId) return parseInt(params.globalSetId, 10);
                        if (ctx && ctx.type === 'globalSet' && ctx.id) return parseInt(ctx.id, 10);
                        return null;
                }
                return null;
            }

            function scopedProtected(resourceType, op) {
                const id = resolveResourceId(resourceType);
                if (!id) return false;
                return !!actions[resourceType + '.' + id + '.' + op];
            }

            // Returns true when at least one resource of the given type has delete
            // protection enabled. Used as a fallback for Craft 5's delete-elements/delete
            // endpoint where the request body contains no sectionId/groupId/volumeId.
            function hasAnyDeleteProtection(type) {
                const prefix = type + '.';
                const suffix = '.delete';
                return Object.keys(actions).some(function(k) {
                    return !!actions[k] && k.indexOf(prefix) === 0 && k.lastIndexOf(suffix) === k.length - suffix.length;
                });
            }


            // Generic element endpoints — Craft 4 CP routes most saves through elements/*
            // e.g. elements/apply-draft (Save button on live entries), elements/save-draft (autosave)
            if (/\/elements\/(apply-draft|save-draft|save)\b/.test(u)) {
                // Never prompt for MFA when publishing a brand-new entry for the first time.
                // config.isUnpublishedDraft is true when the page is editing an unpublished
                // draft (new entry not yet published). Craft's prepareData() also appends
                // provisional=1 only for provisional drafts (existing-entry saves), so the
                // absence of provisional alongside isUnpublishedDraft is a definitive signal
                // that this is a new-entry creation request, not an existing-entry save.
                if (getConfig().isUnpublishedDraft && !params.provisional) return false;

                // Only the explicit "publish" call (apply-draft) should ever trigger MFA on
                // an entry edit page. save-draft (autosave) and bare /elements/save calls
                // are excluded by the WRITE_DENYLIST upstream, but defend in depth here too.
                if (/\/elements\/save-draft\b/.test(u)) return false;

                const et = (params.elementType || '').replace(/\\/g, '\\');
                if (/Entry/i.test(et))     return scopedProtected('entry', 'save');
                if (/Category/i.test(et))  return scopedProtected('category', 'save');
                if (/GlobalSet/i.test(et)) return scopedProtected('globalSet', 'save');
                if (/\bUser\b/i.test(et))  return false;
                // elementType unavailable — fall back to the URL-derived resource context.
                const ctx = config.currentResourceContext;
                if (ctx && ctx.type && ctx.id) {
                    return !!actions[ctx.type + '.' + ctx.id + '.save'];
                }
                return false;
            }

            // Generic element delete (elements/delete, elements/delete-for-site)
            if (/\/elements\/(delete|delete-for-site)\b/.test(u)) {
                const et = (params.elementType || '').replace(/\\/g, '\\');
                if (/Entry/i.test(et))    return scopedProtected('entry', 'delete');
                if (/Category/i.test(et)) return scopedProtected('category', 'delete');
                if (/Asset/i.test(et))    return scopedProtected('asset', 'delete');
                if (/\bUser\b/i.test(et)) return false;
                const ctx = config.currentResourceContext;
                if (ctx && ctx.type && ctx.id) {
                    return !!actions[ctx.type + '.' + ctx.id + '.delete'];
                }
                return false;
            }

            // Scoped: Entries — save / apply-draft (entries controller fallback)
            if (/\/entries\/(save-entry|apply-draft)\b/.test(u)) {
                return scopedProtected('entry', 'save');
            }

            // Scoped: Entries — delete
            if (/\/entries\/delete-entry\b/.test(u)) {
                return scopedProtected('entry', 'delete');
            }

            // Element-indexes bulk actions (e.g. bulk delete).
            // Resolution priority for the resource context:
            //   1. config.currentResourceContext — set when the page is a section/group
            //      index URL (e.g. /entries/articles). This is ONLY reliable after a
            //      full page load at that URL. After Craft CP PJAX navigation the global
            //      window.MfaEnforcerConfig is replaced, so we always call getConfig() here.
            //   2. sourceKeyMap — PHP pre-builds a UUID→{type,id} table for every
            //      protected resource. The request body always carries a 'source' field
            //      (e.g. 'section:UUID' or 'group:UUID'), so this path works even when
            //      the page first loaded at a generic URL (e.g. /entries with no section
            //      path component) and currentResourceContext is null.
            if (/element-indexes\/perform-action/.test(u)) {
                const elementAction = params.elementAction || '';
                if (!/delete/i.test(elementAction)) return false;

                // Path 1: currentResourceContext (reliable after direct URL load or PJAX
                // that navigated to the specific section URL).
                const ctx = getConfig().currentResourceContext;
                if (ctx && ctx.type && ctx.id) {
                    return !!actions[ctx.type + '.' + ctx.id + '.delete'];
                }

                // Path 2: sourceKeyMap — map the 'source' body param (section/group UUID
                // key) to the numeric resource ID that protection settings are stored under.
                const source = params.source || '';
                if (source) {
                    const sourceKeyMap = getConfig().sourceKeyMap || {};
                    const mapped = sourceKeyMap[source];
                    if (mapped && mapped.type && mapped.id) {
                        return !!actions[mapped.type + '.' + mapped.id + '.delete'];
                    }

                    // Path 3: Wildcard source ('*') = "All entries" / "All categories" view.
                    // Read the currently selected rows from the element-index DOM and check
                    // whether any of their section/group cells match a protected name.
                    // sourceKeyMap only contains entries for protected resources, so its
                    // 'name' values are exactly the section names that require MFA.
                    if (source === '*') {
                        const et = params.elementType || '';
                        let resourceType = null;
                        let cellAttr = null;
                        if (/Entry/i.test(et)) { resourceType = 'entry'; cellAttr = 'section'; }
                        else if (/Category/i.test(et)) { resourceType = 'category'; cellAttr = 'group'; }
                        if (!resourceType) return false;

                        const skm = getConfig().sourceKeyMap || {};
                        const protectedNames = new Set();
                        Object.values(skm).forEach(function(v) {
                            if (v.type === resourceType && v.name) protectedNames.add(v.name);
                        });
                        if (protectedNames.size === 0) return false;

                        try {
                            const selectedRows = document.querySelectorAll('tr.sel');
                            for (let i = 0; i < selectedRows.length; i++) {
                                const cell = selectedRows[i].querySelector('td[data-attr="' + cellAttr + '"]');
                                if (!cell) continue;
                                const cellText = (cell.textContent || '').trim();
                                if (protectedNames.has(cellText)) return true;
                            }
                            return false;
                        } catch (_) {
                            // DOM read failed — prompt MFA if any protection exists (safe fallback)
                            return true;
                        }
                    }
                }

                return false;
            }

            // Scoped: Categories — save
            if (/\/categories\/save-category\b/.test(u)) {
                return scopedProtected('category', 'save');
            }

            // Scoped: Categories — delete
            if (/\/categories\/delete-category\b/.test(u)) {
                return scopedProtected('category', 'delete');
            }

            // Scoped: Global sets — save
            if (/\/globals\/(save-global-content|save-set|save-content)\b/.test(u)) {
                return scopedProtected('globalSet', 'save');
            }

            // Scoped: Assets — upload (per volume)
            if (/\/assets\/upload\b/.test(u)) {
                return scopedProtected('asset', 'upload');
            }

            // Scoped: Assets — delete (per volume; covers direct delete-asset route)
            if (/\/assets\/delete-asset\b/.test(u)) {
                return scopedProtected('asset', 'delete');
            }

            // Craft 5: delete-elements/delete (new deletion endpoint introduced in Craft 5.10+)
            // The request body only contains {elementType, elementIds, siteId, ...} — no
            // sectionId/groupId/volumeId.
            if (/\/delete-elements\/delete\b/.test(u)) {
                const et = (params.elementType || '').replace(/\\/g, '\\');

                // Read the 'source' param from the current page URL.
                // Craft appends it to all index URLs:
                //   /entries/testing  → ?source=section%3A<testing-uuid>  (specific section)
                //   /entries          → ?source=*                          (All entries view)
                //   (absent)          → no source available
                let pageSource = '';
                try {
                    pageSource = new URLSearchParams(window.location.search).get('source') || '';
                } catch (_) {}

                // Wildcard DOM scan — used when pageSource === '*' (All entries / All categories
                // / All assets view). Inspects the Section/Group/Volume column of selected rows
                // and returns true if ANY selected row belongs to a protected resource.
                // This matches the requirement: mixed selection (protected + unprotected) → ask MFA;
                // all-unprotected selection → no MFA.
                function wildcardDomCheck(resourceType, cellAttr) {
                    const skm = getConfig().sourceKeyMap || {};
                    const protectedNames = new Set();
                    Object.values(skm).forEach(function(v) {
                        if (v.type === resourceType && v.name) protectedNames.add(v.name);
                    });
                    if (protectedNames.size === 0) return false;
                    try {
                        const selectedRows = document.querySelectorAll('tr.sel');
                        for (let i = 0; i < selectedRows.length; i++) {
                            const cell = selectedRows[i].querySelector('td[data-attr="' + cellAttr + '"]');
                            if (!cell) continue;
                            if (protectedNames.has((cell.textContent || '').trim())) return true;
                        }
                        return false;
                    } catch (_) {
                        // DOM read failed — fall back to broad check; PHP does real per-element gate
                        return hasAnyDeleteProtection(resourceType);
                    }
                }

                if (/Entry/i.test(et)) {
                    // Path 1: exact section ID from currentResourceContext or explicit sectionId in body
                    const id = resolveResourceId('entry');
                    if (id) return !!actions['entry.' + id + '.delete'];

                    // Path 2a: "All entries" wildcard view — scan selected rows' Section column
                    if (pageSource === '*') return wildcardDomCheck('entry', 'section');

                    // Path 2b: specific section UUID in page URL → precise sourceKeyMap lookup
                    if (pageSource) {
                        const skm = getConfig().sourceKeyMap || {};
                        const mapped = skm[pageSource];
                        if (mapped && mapped.type === 'entry' && mapped.id) {
                            return !!actions['entry.' + mapped.id + '.delete'];
                        }
                        // UUID present but NOT in sourceKeyMap → section is not protected
                        return false;
                    }
                    // Path 3: no source param at all — speculative, PHP does real per-element check
                    return hasAnyDeleteProtection('entry');
                }
                if (/Category/i.test(et)) {
                    const id = resolveResourceId('category');
                    if (id) return !!actions['category.' + id + '.delete'];
                    if (pageSource === '*') return wildcardDomCheck('category', 'group');
                    if (pageSource) {
                        const skm = getConfig().sourceKeyMap || {};
                        const mapped = skm[pageSource];
                        if (mapped && mapped.type === 'category' && mapped.id) {
                            return !!actions['category.' + mapped.id + '.delete'];
                        }
                        return false;
                    }
                    return hasAnyDeleteProtection('category');
                }
                if (/Asset/i.test(et)) {
                    const id = resolveResourceId('asset');
                    if (id) return !!actions['asset.' + id + '.delete'];
                    if (pageSource === '*') return wildcardDomCheck('asset', 'volume');
                    if (pageSource) {
                        const skm = getConfig().sourceKeyMap || {};
                        const mapped = skm[pageSource];
                        if (mapped && mapped.type === 'asset' && mapped.id) {
                            return !!actions['asset.' + mapped.id + '.delete'];
                        }
                        return false;
                    }
                    return hasAnyDeleteProtection('asset');
                }
                if (/\bUser\b/i.test(et)) return false;
                // elementType not recognised — fall back to page URL context
                const ctx = getConfig().currentResourceContext;
                if (ctx && ctx.type && ctx.id) {
                    return !!actions[ctx.type + '.' + ctx.id + '.delete'];
                }
                return false;
            }

            return false;
        } catch (_) {
            return false;
        }
    }

    // ---- Garnish modal (matches Craft's elevated-session UX) ----
    let modalState = null;
    function ensureModal() {
        if (modalState) return modalState;
        if (typeof window.Garnish === 'undefined' || typeof window.jQuery === 'undefined') {
            console.warn('[mfa-enforcer] Garnish/jQuery not present — interception disabled.');
            return null;
        }
        const $ = window.jQuery;
        const $form = $('<form class="modal fitted mfa-enforcer-modal" style="min-height:170px;" />');
        const $body = $(`
            <div class="body" style="padding:24px; min-width:520px;">
                <div style="display:flex; align-items:flex-start; gap:16px;">
                    <div class="mfa-enforcer-lock" style="
                        flex:0 0 auto;
                        width:40px;
                        height:40px;
                        display:flex;
                        align-items:center;
                        justify-content:center;
                        color:var(--text-secondary);
                    ">
                        <span data-icon="lock" style="font-size:28px;"></span>
                    </div>

                    <div style="flex:1;">
                        <h2 style="margin:0 0 6px; font-size:16px; font-weight:600;">
                            Two-factor authentication
                        </h2>

                        <p style="margin:0 0 16px; color:var(--text-secondary);">
                            Enter your authentication code to continue.
                        </p>
                    </div>
                </div>
            </div>
        `).appendTo($form);
        const $inputContainer = $('<div class="inputcontainer" style="width:100%; margin-top:6px;" />').appendTo($body);
        const $flex = $('<div style="display:flex; gap:12px; align-items:flex-start; width:100%;" />').appendTo($inputContainer);
        const $flexGrow = $('<div style="flex:1; min-width:0;" />').appendTo($flex);
        const $btnCell = $('<div style="flex:0 0 auto;" />').appendTo($flex);
        const $input = $('<input ' + 'type="text" ' + 'class="text fullwidth" ' + 'inputmode="numeric" ' + 'autocomplete="one-time-code" ' + 'pattern="[0-9 ]*" ' + 'maxlength="10" ' + 'placeholder="123 456" ' + 'style="width:100%; font-size:16px;"' + ' />').appendTo($flexGrow);
        const $submitBtn = (window.Craft && window.Craft.ui) ? window.Craft.ui.createSubmitButton({class: 'disabled', label: 'Submit', spinner: true,}) : $('<button type="submit" class="btn submit">Submit</button>'); $submitBtn.appendTo($btnCell);
        const $error = $('<p class="error" style="' + 'margin:5px 0 0;' + 'min-height:22px;' + 'font-size:13px;' + '" />').appendTo($body);

        const modal = new window.Garnish.Modal($form, {
            closeOtherModals: false,
            autoShow: false,
            // Modal is intentionally LOCKED. The ONLY way to dismiss it is to
            // enter a valid TOTP code and submit successfully — or refresh the
            // page. Esc, clicking the dimmed background, and any other Garnish
            // close path are all disabled here.
            hideOnEsc: false,
            hideOnShadeClick: false,
            onFadeIn: () => setTimeout(() => $input.trigger('focus'), 100),
            onFadeOut: () => {
                $input.val('');
                $error.text('');
                if (modalState && modalState.activeCancel) {
                    const cb = modalState.activeCancel;
                    modalState.activeCancel = null;
                    cb();
                }
            },
        });

        // Belt-and-braces: even if some other handler tries to send an Esc keydown
        // toward the modal form, swallow it here so the modal stays open.
        $form.on('keydown', function (e) {
            if (e.key === 'Escape' || e.keyCode === 27) {
                e.preventDefault();
                e.stopPropagation();
            }
        });

        function setSubmitEnabled(enabled) {
            if (enabled) $submitBtn.removeClass('disabled');
            else $submitBtn.addClass('disabled');
        }
        $input.on('input', () => setSubmitEnabled($input.val().trim().length >= 4));
        $form.on('submit', function (e) {
            e.preventDefault();
            const code = $input.val().trim();
            if (!code) return;
            $submitBtn.addClass('loading');
            $error.text('');
            const handler = modalState && modalState.activeSubmit;
            if (typeof handler !== 'function') return;
            handler(code, function (err) {
                $submitBtn.removeClass('loading');
                if (err) {
                    $error.text(err);
                    if (window.Garnish && window.Garnish.shake) window.Garnish.shake(modal.$container);
                    $input.trigger('select');
                } else {
                    // IMPORTANT: clear activeCancel before hiding the modal. modal.hide()
                    // fades out which triggers onFadeOut, which would otherwise invoke the
                    // cancel callback. For XHR-based deletes, the cancel callback dispatches
                    // error/loadend events on the very XHR we just re-sent — breaking the
                    // Craft element index "refresh list after delete" path. Resolving the
                    // cancel here keeps the success flow clean.
                    if (modalState) modalState.activeCancel = null;
                    modal.hide();
                }
            });
        });

        modalState = { modal, $input, $error, $submitBtn, activeSubmit: null, activeCancel: null, setSubmitEnabled };
        return modalState;
    }

    function showModal(onSubmit, onCancel) {
        const state = ensureModal();
        if (!state) return;
        state.$input.val('');
        state.$error.text('');
        state.setSubmitEnabled(false);
        state.activeSubmit = onSubmit;
        state.activeCancel = onCancel || null;
        state.modal.show();
    }

    // ---- Enrolment modal (shown when the user is not enrolled in MFA) ----
    let enrollModalState = null;
    function ensureEnrollModal() {
        if (enrollModalState) return enrollModalState;
        if (typeof window.Garnish === 'undefined' || typeof window.jQuery === 'undefined') return null;
        const $ = window.jQuery;
        const $form = $('<form class="modal fitted mfa-enforcer-enrol-modal" />');

        const $body = $(`
            <div class="body" style="
                padding:28px;
                min-width:520px;
                text-align:start;
            ">

                <h2 style="
                    margin:0 0 10px;
                    font-size:18px;
                    font-weight:600;
                ">
                    Two-step verification required
                </h2>

                <p style="
                    margin:0 0 8px;
                    color:var(--text-secondary);
                ">
                    You need to enable Two-Step Verification before performing this action.
                </p>

                <p style="
                    margin:0;
                    color:var(--text-secondary);
                ">
                    Please set it up via
                    <strong>My Account -> Password &amp; Verification</strong>.
                </p>

            </div>
        `).appendTo($form);

        const $btnRow = $('<div style="\
            display:flex;\
            justify-content:end;\
            align-items:center;\
            gap:12px;\
            margin-top:22px;\
        " />').appendTo($body);

        const $cancel = $('<button type="button" class="btn">Cancel</button>')
            .appendTo($btnRow);

        const $goto = $('<button type="button" class="btn submit">' + 'Go to Password &amp; Verification' + '</button>').appendTo($btnRow);

        const modal = new window.Garnish.Modal($form, {
            closeOtherModals: false,
            autoShow: false,
            hideOnEsc: true,
            hideOnShadeClick: true,
            onFadeIn: () => {},
        });

        $goto.on('click', function () {
            try {
                const url = (getConfig() && getConfig().setupUrl) || '/admin/myaccount/password';
                window.location.href = url;
            } catch (_) {
                window.location.href = '/admin/myaccount/password';
            }
        });
        $cancel.on('click', function () { modal.hide(); });

        enrollModalState = { modal };
        return enrollModalState;
    }

    function showEnrollModal() {
        const s = ensureEnrollModal();
        if (!s) return;
        s.modal.show();
    }

    function verifyCode(code, callback) {
        const body = new URLSearchParams();
        body.append('code', code);
        body.append('actionKey', 'universal');
        body.append(config.csrfTokenName, config.csrfToken);

        fetch(config.verifyUrl, {
            method: 'POST',
            credentials: 'same-origin',
            headers: {
                'Accept': 'application/json',
                'X-Requested-With': 'XMLHttpRequest',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: body.toString(),
        }).then(r => r.json().then(j => ({ ok: r.ok, json: j })))
          .then(({ ok, json }) => {
              if (ok && json.success && json.token) callback(null, json.token);
              else callback(json.error || 'Verification failed.', null);
          })
          .catch(() => callback('Network error. Please try again.', null));
    }

    function injectTokenInput(form, token) {
        let input = form.querySelector('input[name="mfaEnforcerToken"]');
        if (!input) {
            input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'mfaEnforcerToken';
            form.appendChild(input);
        }
        input.value = token;
    }

    function formActionValue(form) {
        const input = form.querySelector('input[name="action"]');
        return input ? input.value : (form.getAttribute('action') || '');
    }

    function challengeForm(form, originalSubmit, submitArgs) {
        const action = formActionValue(form);

        // -------------------------------------------------
        // Craft 4 discard changes uses the same entry form
        // submit flow as save-entry. Detect the actual
        // clicked button instead of the form action.
        // -------------------------------------------------
        const activeEl = document.activeElement;

        if (
            activeEl &&
            (
                /discard/i.test(activeEl.textContent || '') ||
                /discard/i.test(activeEl.value || '') ||
                /discard/i.test(activeEl.name || '') ||
                /discard/i.test(activeEl.dataset.action || '')
            )
        ) {
            return originalSubmit.apply(form, submitArgs || []);
        }

        if (!isWriteFormAction(action)) {
            return originalSubmit.apply(form, submitArgs || []);
        }

        if (/elements\/delete\b/i.test(action) && formMentionsDraft(form)) {
            return originalSubmit.apply(form, submitArgs || []);
        }

        const actionUrl = '/actions/' + action;
        if (!isActionProtectedBySettings(actionUrl, extractFormParams(form))) {
            return originalSubmit.apply(form, submitArgs || []);
        }
        // If user is not enrolled, show the enrol modal (only for protected actions).
        if (!getConfig().userEnrolled) {
            showEnrollModal();
            return;
        }
        showModal(function (code, done) {
            verifyCode(code, function (err, token) {
                if (err) { done(err); return; }
                storeRecentMfaToken(token);
                injectTokenInput(form, token);
                form.dataset.mfaEnforcerConfirmed = '1';
                done(null);
                originalSubmit.apply(form, submitArgs || []);
            });
        });
    }

    // ---- Programmatic form.submit() / requestSubmit() ----
    const origFormSubmit = HTMLFormElement.prototype.submit;
        HTMLFormElement.prototype.submit = function () {

            if (this.dataset.mfaEnforcerConfirmed === '1') {
                return origFormSubmit.apply(this, arguments);
            }

            const cachedToken = getRecentMfaToken();

            if (cachedToken) {
                injectTokenInput(this, cachedToken);
                this.dataset.mfaEnforcerConfirmed = '1';

                return origFormSubmit.apply(this, arguments);
            }

            return challengeForm(this, origFormSubmit, arguments);
        };
    if (typeof HTMLFormElement.prototype.requestSubmit === 'function') {
        const origRequestSubmit = HTMLFormElement.prototype.requestSubmit;
        HTMLFormElement.prototype.requestSubmit = function () {

            if (this.dataset.mfaEnforcerConfirmed === '1') {
                return origRequestSubmit.apply(this, arguments);
            }

            const cachedToken = getRecentMfaToken();

            if (cachedToken) {
                injectTokenInput(this, cachedToken);
                this.dataset.mfaEnforcerConfirmed = '1';

                return origRequestSubmit.apply(this, arguments);
            }

            return challengeForm(this, origRequestSubmit, arguments);
        };
    }

    // ---- Submit-event interception (Enter key, etc.) ----
    document.addEventListener('submit', function (e) {
        const form = e.target;
        if (!form || form.tagName !== 'FORM') return;
        if (form.dataset.mfaEnforcerConfirmed === '1') {
            return;
        }

        const action = formActionValue(form);

        const activeEl = document.activeElement;

        if (
            activeEl &&
            (
                /discard/i.test(activeEl.textContent || '') ||
                /discard/i.test(activeEl.value || '') ||
                /discard/i.test(activeEl.name || '') ||
                /discard/i.test(activeEl.dataset.action || '')
            )
        ) {
            return;
        }

        if (!isWriteFormAction(action)) {
            return;
        }

        if (/elements\/delete\b/i.test(action) && formMentionsDraft(form)) {
            return;
        }

        if (!isActionProtectedBySettings('/actions/' + action, extractFormParams(form))) {
            return;
        }

        // If not enrolled, show the enrol modal instead of asking for a code.
        if (!getConfig().userEnrolled) {
            e.preventDefault();
            e.stopPropagation();
            showEnrollModal();
            return;
        }

        // Always show the MFA modal for protected actions.
        e.preventDefault();
        e.stopPropagation();
        showModal(function (code, done) {
            verifyCode(code, function (err, token) {
                if (err) { done(err); return; }
                injectTokenInput(form, token);
                form.dataset.mfaEnforcerConfirmed = '1';
                done(null);
                storeRecentMfaToken(token);

                // IMPORTANT:
                // Use requestSubmit() so Craft keeps its draft lifecycle intact
                if (typeof form.requestSubmit === 'function') {
                    form.requestSubmit();
                } else {
                    const submitEvent = new Event('submit', {
                        bubbles: true,
                        cancelable: true,
                    });

                    form.dispatchEvent(submitEvent);
                }
            });
        });
    }, true);

    // ---- Click interception for Utilities → Project Config "Reapply everything" ----
    document.addEventListener('click', function (e) {
        if (!e || !e.target) return;
        const btn = (typeof e.target.closest === 'function') ? e.target.closest('[data-action="config-sync"]') : null;
        if (!btn) return;

        // Ensure this action is actually protected in settings
        try {
            const _cfg = getConfig();
            if (!_cfg || !_cfg.applies || !_cfg.protectedActions) return;
            if (!_cfg.protectedActions['utilities.projectConfig.reapply']) return;
        } catch (_) {
            return;
        }

        // Buttons rendered by Craft may include a data-params attribute JSON-encoded
        const paramsAttr = btn.getAttribute('data-params') || btn.dataset.params || null;
        let params = null;
        if (paramsAttr) {
            try { params = (typeof paramsAttr === 'string') ? JSON.parse(paramsAttr) : paramsAttr; } catch (_) { params = null; }
        }
        const isForce = params && (params.force === 1 || params.force === '1' || params.force === true);
        if (!isForce) return;

        if (btn.dataset.mfaEnforcerConfirmed === '1') return;

        // If user not enrolled, show enrol modal instead of prompting for code.
        if (!getConfig().userEnrolled) {
            e.preventDefault();
            e.stopPropagation();
            showEnrollModal();
            return;
        }

        // Prevent duplicate modals for the same button
        if (btn.__mfaEnforcerPending) return;
        btn.__mfaEnforcerPending = true;

        e.preventDefault();
        e.stopPropagation();

        showModal(function (code, done) {
            verifyCode(code, function (err, token) {
                btn.__mfaEnforcerPending = false;
                if (err) { done(err); return; }
                storeRecentMfaToken(token);
                done(null);
                btn.dataset.mfaEnforcerConfirmed = '1';
                // Re-dispatch the original click after a short delay to avoid re-entry issues
                setTimeout(function () { btn.click(); }, 10);
            });
        }, function () {
            btn.__mfaEnforcerPending = false;
        });
    }, true);

    // ---- Click interception for Project Config "Download" button ----
    document.addEventListener('click', function (e) {
        if (!e || !e.target) return;
        const btn = (typeof e.target.closest === 'function') ? e.target.closest('#download') : null;
        if (!btn) return;

        try {
            const _cfg = getConfig();
            if (!_cfg || !_cfg.applies || !_cfg.protectedActions) return;
            if (!_cfg.protectedActions['utilities.projectConfig.download']) return;
        } catch (_) { return; }

        if (btn.__mfaEnforcerConfirmed === '1') return;

        e.preventDefault();
        e.stopPropagation();

        if (!getConfig().userEnrolled) {
            showEnrollModal();
            return;
        }

        if (btn.__mfaEnforcerPending) return;
        btn.__mfaEnforcerPending = true;

        showModal(function (code, done) {
            verifyCode(code, function (err, token) {
                btn.__mfaEnforcerPending = false;
                if (err) { done(err); return; }
                done(null);
                btn.__mfaEnforcerConfirmed = '1';
                // Call Craft.downloadFromUrl with token appended to params
                const params = {};
                if (Craft.csrfTokenName) params[Craft.csrfTokenName] = Craft.csrfTokenValue;
                params['mfaEnforcerToken'] = token;
                if (typeof Craft.downloadFromUrl === 'function') {
                    Craft.downloadFromUrl('GET', (getConfig() && getConfig().actionUrls && getConfig().actionUrls['project-config/download']) || (window && window.Craft && window.Craft.getActionUrl && window.Craft.getActionUrl('project-config/download')) || '', params);
                } else {
                    // Fallback: build and navigate to URL
                    const url = (typeof window.Craft !== 'undefined' && window.Craft.getActionUrl) ? window.Craft.getActionUrl('project-config/download') : '';
                    const query = Object.keys(params).map(k => encodeURIComponent(k) + '=' + encodeURIComponent(params[k])).join('&');
                    window.location.href = url + (url.indexOf('?') === -1 ? '?' : '&') + query;
                }
            });
        }, function () {
            btn.__mfaEnforcerPending = false;
        });
    }, true);

    // ---- XHR interception ----
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    const origSetHeader = XMLHttpRequest.prototype.setRequestHeader;

    XMLHttpRequest.prototype.open = function (method, url) {
        this.__mfaEnforcerMethod = (method || '').toUpperCase();
        this.__mfaEnforcerUrl = url;
        this.__mfaEnforcerHeaders = [];
        return origOpen.apply(this, arguments);
    };
    XMLHttpRequest.prototype.setRequestHeader = function (name, value) {
        if (this.__mfaEnforcerHeaders) this.__mfaEnforcerHeaders.push([name, value]);
        return origSetHeader.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
        const xhr = this;
        const method = xhr.__mfaEnforcerMethod;
        const url = xhr.__mfaEnforcerUrl || '';
        if ((method !== 'POST' && method !== 'DELETE') || xhr.__mfaEnforcerPassed) return origSend.apply(xhr, arguments);
        if (!isWriteUrl(url)) {
            return origSend.apply(xhr, arguments);
        }

        if (isDeleteWithDraftId(url, arguments[0])) {
            return origSend.apply(xhr, arguments);
        }

        if (!isActionProtectedBySettings(url, extractBodyParams(arguments[0]))) {
            return origSend.apply(xhr, arguments);
        }

        const sendArgs = arguments;
        // If user not enrolled, show the enrol modal and abort the request.
        if (!getConfig().userEnrolled) {
            try { showEnrollModal(); } catch (_) {}
            return origSend.apply(xhr, arguments);
        }

        // ---- Asset upload: batch-aware handling ----
        // Each file in a multi-file upload is a separate XHR. To avoid
        // prompting for MFA once per file, we:
        //   1. Use a 30-second upload token cache (server does NOT consume
        //      upload tokens, only validates by TTL).
        //   2. Queue concurrent XHRs that arrive while the modal is open;
        //      they all resume with the same token when the user confirms.
        let decodedUrl;
        try { decodedUrl = decodeURIComponent(url); } catch (_) { decodedUrl = url; }
        const isAssetUpload = /\/assets\/upload\b/i.test(decodedUrl);

        if (isAssetUpload) {
            // 1. Cached upload token (covers sequential uploads within 30s)
            const uploadToken = getRecentMfaToken();
            if (uploadToken) {
                xhr.__mfaEnforcerPassed = true;
                const headers = xhr.__mfaEnforcerHeaders ? xhr.__mfaEnforcerHeaders.slice() : [];
                origOpen.call(xhr, method, url, true);
                for (const [n, v] of headers) origSetHeader.call(xhr, n, v);
                origSetHeader.call(xhr, TOKEN_HEADER, uploadToken);
                return origSend.apply(xhr, sendArgs);
            }

            // 2. Modal already open — queue this XHR to resume when token is ready
            if (uploadModalPending) {
                pendingUploadCallbacks.push(function (token) {
                    if (!token) {
                        try { Object.defineProperty(xhr, 'status', { value: 0, configurable: true }); } catch (_) {}
                        if (typeof xhr.onerror === 'function') xhr.onerror(new Event('error'));
                        xhr.dispatchEvent(new Event('error'));
                        xhr.dispatchEvent(new Event('loadend'));
                        return;
                    }
                    xhr.__mfaEnforcerPassed = true;
                    const headers = xhr.__mfaEnforcerHeaders ? xhr.__mfaEnforcerHeaders.slice() : [];
                    origOpen.call(xhr, method, url, true);
                    for (const [n, v] of headers) origSetHeader.call(xhr, n, v);
                    origSetHeader.call(xhr, TOKEN_HEADER, token);
                    origSend.apply(xhr, sendArgs);
                });
                return;
            }

            // 3. Show MFA modal; all concurrently queued XHRs resume on success
            uploadModalPending = true;
            showModal(function (code, done) {
                verifyCode(code, function (err, token) {
                    if (err) { done(err); return; }
                    done(null);
                    storeRecentMfaToken(token);
                    notifyUploadCallbacks(token); // resume queued uploads, clears flag
                    const headers = xhr.__mfaEnforcerHeaders ? xhr.__mfaEnforcerHeaders.slice() : [];
                    xhr.__mfaEnforcerPassed = true;
                    origOpen.call(xhr, method, url, true);
                    for (const [n, v] of headers) origSetHeader.call(xhr, n, v);
                    origSetHeader.call(xhr, TOKEN_HEADER, token);
                    origSend.apply(xhr, sendArgs);
                });
            }, function () {
                notifyUploadCallbacks(null); // cancel queued uploads, clears flag
                try { Object.defineProperty(xhr, 'status', { value: 0, configurable: true }); } catch (_) {}
                if (typeof xhr.onerror === 'function') xhr.onerror(new Event('error'));
                xhr.dispatchEvent(new Event('error'));
                xhr.dispatchEvent(new Event('loadend'));
            });
            return;
        }

        // ---- Non-upload: standard single-use token handling ----
        const cachedToken = getRecentMfaToken();

        if (cachedToken) {
            xhr.__mfaEnforcerPassed = true;

            const headers = xhr.__mfaEnforcerHeaders
                ? xhr.__mfaEnforcerHeaders.slice()
                : [];

            origOpen.call(xhr, method, url, true);

            for (const [n, v] of headers) {
                origSetHeader.call(xhr, n, v);
            }

            origSetHeader.call(xhr, TOKEN_HEADER, cachedToken);

            return origSend.apply(xhr, arguments);
        }
        showModal(function (code, done) {
            verifyCode(code, function (err, token) {
                if (err) { done(err); return; }
                done(null);
                storeRecentMfaToken(token);
                const headers = xhr.__mfaEnforcerHeaders ? xhr.__mfaEnforcerHeaders.slice() : [];
                xhr.__mfaEnforcerPassed = true;
                origOpen.call(xhr, method, url, true);
                for (const [n, v] of headers) origSetHeader.call(xhr, n, v);
                origSetHeader.call(xhr, TOKEN_HEADER, token);
                origSend.apply(xhr, sendArgs);
            });
        }, function () {
            try { Object.defineProperty(xhr, 'status', { value: 0, configurable: true }); } catch (_) {}
            if (typeof xhr.onerror === 'function') xhr.onerror(new Event('error'));
            xhr.dispatchEvent(new Event('error'));
            xhr.dispatchEvent(new Event('loadend'));
        });
    };

    // ---- fetch interception ----
    const origFetch = window.fetch;
    window.fetch = function (input, init) {
        const url = typeof input === 'string' ? input : (input && input.url) || '';
        const method = ((init && init.method) || (input && input.method) || 'GET').toUpperCase();
        if (method !== 'POST' && method !== 'DELETE') return origFetch.apply(this, arguments);
        if (!isWriteUrl(url)) {
            return origFetch.apply(this, arguments);
        }

        if (isDeleteWithDraftId(url, init && init.body)) {
            return origFetch.apply(this, arguments);
        }

        const bodyParams = extractBodyParams(
            (init && init.body) || null
        );

        if (!isActionProtectedBySettings(url, bodyParams)) {
            return origFetch.apply(this, arguments);
        }

        const newInit = Object.assign({}, init);
        const headers = new Headers(newInit.headers || {});

        // Already verified request
        if (headers.has(TOKEN_HEADER)) {
            return origFetch.apply(this, arguments);
        }

        const cachedToken = getRecentMfaToken();

        if (cachedToken) {
            headers.set(TOKEN_HEADER, cachedToken);
            newInit.headers = headers;

            return origFetch.call(window, input, newInit);
        }

        // If user not enrolled, show the enrol modal and reject the fetch promise.
        if (!getConfig().userEnrolled) {
            try { showEnrollModal(); } catch (_) {}
            return Promise.reject(new Error('MFA enrollment required'));
        }

        return new Promise(function (resolve, reject) {
            showModal(function (code, done) {
                verifyCode(code, function (err, token) {
                    if (err) { done(err); return; }
                    done(null);
                    storeRecentMfaToken(token);
                    headers.set(TOKEN_HEADER, token);
                    newInit.headers = headers;
                    origFetch.call(window, input, newInit).then(function (response) {
                        if (response && response.ok) {
                            resolve(response);
                            return;
                        }
                        // If response indicates MFA was required, prompt and retry once.
                        const tryParse = () => response.clone().json().catch(() => null);
                        tryParse().then(function (json) {
                            const msg = json && (json.error || json.message || '');
                            if (response && (response.status === 401 || response.status === 409 || /mfa/i.test(msg))) {
                                showModal(function (code, done) {
                                    verifyCode(code, function (err, token) {
                                        if (err) { done(err); return; }
                                        done(null);
                                        headers.set(TOKEN_HEADER, token);
                                        newInit.headers = headers;
                                        origFetch.call(window, input, newInit).then(resolve, reject);
                                    });
                                }, function () { reject(new Error('MFA confirmation cancelled.')); });
                            } else {
                                resolve(response);
                            }
                        });
                    }, reject);
                });
            }, function () {
                reject(new Error('MFA confirmation cancelled.'));
            });
        });
    };
})();
