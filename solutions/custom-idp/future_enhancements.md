# Future enhancements

* Implement automated unit and integration testing
* Create helper utility for adding, updating, and removing identity providers and user records in DynamoDB. 
  * Also support bulk adding and updating user records from CSV
* Group-based assignments
* CLI utility for managing users, bulk-adding and/or synchronizing users from CSV
* Web interface for 
  
## Group based assignments design

* IAM role remains associated with individual user, provider, or IdP attribute
* `identity_provider` table records have optional boolean field within the `config` map, `user_groups`. When set, the IdP module will query/return a list of groups the user is a member of (if supported). Additionally, a list of groups can be stored in the `users` record as a list. The final list of groups from `user` and IdP would be combined.
    * This will ONLY be supported with LOGICAL directories. The user’s HomeDirectoryType must be set to LOGICAL for group processing to happen.
    * For security, scopedown policy will automatically be applied. Scope statement will initially contain no actions
* A separate DynamoDB table has mappings of groups to logical home directories. Based on the list of group memberships returned, The identity provider module will retrieve a list of matching group records from the `group_mappings` table. This will be used to generate a list of Logical directories (merging duplicates).
    * The directory list will be merged with any items in the record from the `users`
* The final AWS transfer response with mappings will be returned. 
* DynamoDB table `group_mappings`
    * Partition Key: `identity_provider_key` (Question: Should we make groups idp-specific?)
    * Sort Key: `group_name`
    * Attribute: `group_mappings` (List)
        * Map [`entry, target, scopedown_policy_entries`]
            **Note:** scopedown-policy-entries is optional and has no effect on EFS
            TODO: Estimate max response size to see if this is feasible


