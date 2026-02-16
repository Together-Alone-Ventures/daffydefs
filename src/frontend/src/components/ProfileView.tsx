import { useState } from "react";

interface ProfileData {
  owner: string;
  email: string;
  birthdate: string;
  gender: string;
  display_name: string;
}

interface ProfileViewProps {
  profile: ProfileData;
  profileCanisterId: string;
  onUpdate: (input: {
    email: string;
    birthdate: string;
    gender: string;
    display_name: string;
  }) => Promise<void>;
  onDelete: () => Promise<void>;
  loading: boolean;
  error: string | null;
}

export default function ProfileView({
  profile,
  profileCanisterId,
  onUpdate,
  onDelete,
  loading,
  error,
}: ProfileViewProps) {
  const [editing, setEditing] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [displayName, setDisplayName] = useState(profile.display_name);
  const [email, setEmail] = useState(profile.email);
  const [birthdate, setBirthdate] = useState(profile.birthdate);
  const [gender, setGender] = useState(profile.gender);

  const handleSave = async () => {
    await onUpdate({
      display_name: displayName,
      email,
      birthdate,
      gender,
    });
    setEditing(false);
  };

  const handleDelete = async () => {
    await onDelete();
  };

  const isValid = displayName.length >= 2 && displayName.length <= 30;

  if (confirmDelete) {
    return (
      <div className="card">
        <h2>Delete Profile?</h2>
        <p className="warning-text">
          This will permanently delete your profile canister and all its data.
          Your challenges and comments on the bulletin board will remain but show as "[deleted user]".
        </p>
        <p className="muted">You can rejoin later with a new profile.</p>

        {error && <p className="error">{error}</p>}

        <div className="button-row">
          <button
            className="button button-danger"
            onClick={handleDelete}
            disabled={loading}
          >
            {loading ? "Deleting..." : "Yes, Delete My Profile"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => setConfirmDelete(false)}
            disabled={loading}
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  if (editing) {
    return (
      <div className="card">
        <h2>Edit Profile</h2>

        <div className="form-group">
          <label>Display Name *</label>
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            maxLength={30}
            disabled={loading}
          />
        </div>

        <div className="form-group">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            disabled={loading}
          />
        </div>

        <div className="form-group">
          <label>Birthdate</label>
          <input
            type="date"
            value={birthdate}
            onChange={(e) => setBirthdate(e.target.value)}
            disabled={loading}
          />
        </div>

        <div className="form-group">
          <label>Gender</label>
          <select value={gender} onChange={(e) => setGender(e.target.value)} disabled={loading}>
            <option value="">Select...</option>
            <option value="M">Male</option>
            <option value="F">Female</option>
            <option value="NB">Non-binary</option>
            <option value="O">Other</option>
            <option value="P">Prefer not to say</option>
          </select>
        </div>

        {error && <p className="error">{error}</p>}

        <div className="button-row">
          <button
            className="button button-primary"
            onClick={handleSave}
            disabled={!isValid || loading}
          >
            {loading ? "Saving..." : "Save Changes"}
          </button>
          <button
            className="button button-secondary"
            onClick={() => {
              setEditing(false);
              setDisplayName(profile.display_name);
              setEmail(profile.email);
              setBirthdate(profile.birthdate);
              setGender(profile.gender);
            }}
            disabled={loading}
          >
            Cancel
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="card">
      <h2>Your Profile</h2>

      <div className="profile-field">
        <span className="field-label">Display Name</span>
        <span className="field-value">{profile.display_name}</span>
      </div>

      <div className="profile-field">
        <span className="field-label">Email</span>
        <span className="field-value">{profile.email || "—"}</span>
      </div>

      <div className="profile-field">
        <span className="field-label">Birthdate</span>
        <span className="field-value">{profile.birthdate || "—"}</span>
      </div>

      <div className="profile-field">
        <span className="field-label">Gender</span>
        <span className="field-value">{profile.gender || "—"}</span>
      </div>

      <div className="profile-field">
        <span className="field-label">Profile Canister</span>
        <span className="field-value mono">{profileCanisterId}</span>
      </div>

      {error && <p className="error">{error}</p>}

      <div className="button-row">
        <button className="button button-primary" onClick={() => setEditing(true)}>
          Edit Profile
        </button>
        <button
          className="button button-danger-outline"
          onClick={() => setConfirmDelete(true)}
        >
          Delete Profile
        </button>
      </div>

      <div className="placeholder" style={{ marginTop: "1.5rem" }}>
        <p>Bulletin board coming in Phase 3b...</p>
      </div>
    </div>
  );
}
