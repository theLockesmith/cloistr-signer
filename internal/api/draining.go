package api

// StartDraining marks this replica as shutting down: /health/ready fails from
// now on so Kubernetes moves traffic to the other replica, while requests
// already routed here keep being served.
func (h *Handler) StartDraining() {
	h.draining.Store(true)
}
