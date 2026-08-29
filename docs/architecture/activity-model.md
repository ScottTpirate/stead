# Activity model

Activity is a contextual, rebuildable, authorized projection of minimal domain events. It uses canonical verbs/subjects, actor/requester/task/delegation context, correlation/causation, label reference, and source event checkpoint. It is not a Project tab or system of record. Unauthorized activities and aggregates are absent, and rebuild/rollback follows the event contract.
