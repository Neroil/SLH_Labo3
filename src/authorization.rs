//! Wrapper d'appel à Casbin pour la vérification statique
//! des conventions objet-action

use casbin::CoreApi;
use log::{error, info};
use serde::Serialize;
use serde_json::json;
use thiserror::Error;

use crate::models::{MedicalReport, Role, UserData};

const CONFIG: &str = "access_control/model.conf";
const POLICY: &str = "access_control/policy.csv";

/// Un enforcer Casbin
pub struct Enforcer(casbin::Enforcer);

type CasbinResult = Result<(), AccessDenied>;

/// Une erreur sans détails en cas d'accès refusé
#[derive(Debug, Error)]
#[error("Accès refusé.")]
pub struct AccessDenied;

/// Un contexte contenant une référence à un enforcer et à un sujet.
pub struct Context<'ctx> {
    enforcer: &'ctx Enforcer,
    subject: &'ctx UserData,
}

impl Enforcer {
    pub fn load() -> Result<Self, casbin::Error> {
        let mut enforcer = futures::executor::block_on(casbin::Enforcer::new(CONFIG, POLICY))?;
        futures::executor::block_on(enforcer.load_policy())?;
        Ok(Enforcer(enforcer))
    }

    pub fn with_subject<'ctx>(&'ctx self, subject: &'ctx UserData) -> Context<'ctx> {
        Context {
            enforcer: self,
            subject,
        }
    }
}

impl Context<'_> {
    fn enforce<O>(&self, object: O, action: &str) -> CasbinResult
    where
        O: Serialize + std::fmt::Debug + std::hash::Hash,
    {
        let subject = self.subject;

        info!(
            "Enforcing {}",
            json!({ "sub": subject, "obj": &object, "act": action })
        );
        match self.enforcer.0.enforce((subject, &object, action)) {
            Err(e) => {
                error!("Casbin error: {e:?}");
                Err(AccessDenied)
            }
            Ok(r) => {
                info!("Granted: {r}");
                if r {
                    Ok(())
                } else {
                    Err(AccessDenied)
                }
            }
        }
    }

    pub fn read_data(&self, patient: &UserData) -> CasbinResult {
        self.enforce(patient, "read-data")
    }

    pub fn update_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "update-data")
    }

    pub fn delete_data(&self, target: &UserData) -> CasbinResult {
        self.enforce(target, "delete-data")
    }

    pub fn add_report(&self, patient: &UserData, report: &MedicalReport) -> CasbinResult {
        self.enforce(
            json!({ "patient": patient, "report": report }),
            "add-report",
        )
    }

    pub fn read_report(&self, report: &MedicalReport, patient: &UserData) -> CasbinResult {
        self.enforce(json!({"report": report, "patient": patient}), "read-report")
    }

    pub fn update_report(&self, report: &MedicalReport) -> CasbinResult {
        self.enforce(report, "update-report")
    }

    pub fn update_role(&self, target: &UserData, role: Role) -> CasbinResult {
        self.enforce(json!({ "target": target, "role": role }), "update-role")
    }

    pub fn add_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "add-doctor")
    }

    pub fn remove_doctor(&self, target: &UserData, doctor: &UserData) -> CasbinResult {
        self.enforce(json!({"patient": target, "doctor": doctor}), "remove-doctor")
    }
}

/// Tests unitaires pour l'implémentation de Casbin
#[cfg(test)]
mod test {
    use super::*;
    use crate::models::{
        BloodType, PersonalData, Role, UserData, UserID, MedicalReport, ReportID, MedicalFolder,
    };
    use crate::utils::input_validation::{AVSNumber, Username};
    use crate::utils::password_utils::hash;

    fn create_test_user(id: UserID, username: &str, role: Role, has_folder: bool) -> UserData {
        let medical_folder = if has_folder {
            Some(MedicalFolder {
                personal_data: PersonalData {
                    avs_number: AVSNumber::try_from("756.1234.5678.97".to_string()).unwrap(),
                    blood_type: BloodType::A,
                },
                doctors: Default::default(),
            })
        } else {
            None
        };

        UserData {
            id,
            role,
            username: Username::new(username.to_string()),
            password: hash("dummy"),
            medical_folder,
        }
    }

    fn setup() -> (Enforcer, UserData, UserData, UserData) {
        let enforcer = Enforcer::load().unwrap();

        let admin = create_test_user(UserID::new(), "admin", Role::Admin, false);
        let patient = create_test_user(UserID::new(), "patient", Role::Patient, true);
        let doctor = create_test_user(UserID::new(), "doctor", Role::Doctor, false);

        (enforcer, admin, patient, doctor)
    }

    fn create_test_report(author: UserID, patient: UserID, title: &str) -> MedicalReport {
        MedicalReport {
            id: ReportID::new(),
            title: title.to_string(),
            author,
            patient,
            content: "Test content".to_string(),
        }
    }

    #[test]
    fn test_admin_permissions() {
        let (enforcer, admin, patient, doctor) = setup();
        let ctx = enforcer.with_subject(&admin);

        // Admin should be able to read any user's data
        assert!(ctx.read_data(&patient).is_ok());
        assert!(ctx.read_data(&doctor).is_ok());
        assert!(ctx.read_data(&admin).is_ok());

        // Admin should be able to update any user's data
        assert!(ctx.update_data(&patient).is_ok());
        assert!(ctx.update_data(&doctor).is_ok());
        assert!(ctx.update_data(&admin).is_ok());

        // Admin should be able to delete any user's data
        assert!(ctx.delete_data(&patient).is_ok());
        assert!(ctx.delete_data(&doctor).is_ok());
        assert!(ctx.delete_data(&admin).is_ok());

        // Admin should be able to update any user's role
        assert!(ctx.update_role(&patient, Role::Doctor).is_ok());
        assert!(ctx.update_role(&doctor, Role::Patient).is_ok());
        assert!(ctx.update_role(&patient, Role::Admin).is_ok());

        // Admin should be able to manage doctor assignments
        assert!(ctx.add_doctor(&patient, &doctor).is_ok());
        assert!(ctx.remove_doctor(&patient, &doctor).is_ok());

        // Admin should be able to manage reports
        let report = MedicalReport {
            id: ReportID::new(),
            title: "Admin Report".to_string(),
            author: admin.id,
            patient: patient.id,
            content: "Test content".to_string(),
        };
        assert!(ctx.add_report(&patient, &report).is_ok());
        assert!(ctx.read_report(&report, &patient).is_ok());
        assert!(ctx.update_report(&report).is_ok());
    }

    #[test]
    fn test_patient_permissions() {
        let (enforcer, _, patient, doctor) = setup();
        let ctx = enforcer.with_subject(&patient);

        // Own data access
        assert!(ctx.read_data(&patient).is_ok());
        assert!(ctx.update_data(&patient).is_ok());
        assert!(ctx.delete_data(&patient).is_ok());

        // Doctor management
        assert!(ctx.add_doctor(&patient, &doctor).is_ok());
        assert!(ctx.remove_doctor(&patient, &doctor).is_ok());

        // Cross-patient restrictions
        let other_patient = create_test_user(UserID::new(), "other", Role::Patient, true);
        assert!(ctx.read_data(&other_patient).is_err());
        assert!(ctx.update_role(&patient, Role::Doctor).is_err());

        // Report management
        let report = create_test_report(patient.id, patient.id, "Patient Report");
        assert!(ctx.add_report(&patient, &report).is_err());
    }

    #[test]
    fn test_doctor_permissions() {
        let (enforcer, _, patient, doctor) = setup();
        let ctx = enforcer.with_subject(&doctor);
        let report = create_test_report(doctor.id, patient.id, "Test Report");

        // Report permissions
        assert!(ctx.add_report(&patient, &report).is_ok());
        assert!(ctx.read_report(&report, &patient).is_ok());
        assert!(ctx.update_report(&report).is_ok());
    }

    #[test]
    fn test_doctor_patient_interactions() {
        let (enforcer, _, mut patient, doctor) = setup();
        let ctx = enforcer.with_subject(&doctor);

        // Pre-assignment restrictions
        assert!(ctx.read_data(&patient).is_err());

        // Assignment
        if let Some(ref mut folder) = patient.medical_folder {
            folder.doctors.insert(doctor.id);
        }
        assert!(ctx.read_data(&patient).is_ok());

        // Maintaining permissions
        assert!(ctx.update_data(&patient).is_err());
        let report = create_test_report(doctor.id, patient.id, "Medical Report");
        assert!(ctx.add_report(&patient, &report).is_ok());
        assert!(ctx.update_report(&report).is_ok());
        assert!(ctx.delete_data(&patient).is_err());
    }

    #[test]
    fn test_report_access_control() {
        let (enforcer, _, patient, doctor) = setup();
        let other_doctor = create_test_user(UserID::new(), "other_doctor", Role::Doctor, false);

        let report = create_test_report(doctor.id, patient.id, "Medical Report");

        // Doctor's report access
        let author_ctx = enforcer.with_subject(&doctor);
        assert!(author_ctx.read_report(&report, &patient).is_ok());
        assert!(author_ctx.update_report(&report).is_ok());

        // Another doctor's report restrictions
        let other_ctx = enforcer.with_subject(&other_doctor);
        assert!(other_ctx.read_report(&report, &patient).is_err());

        // Patient's report access
        let patient_ctx = enforcer.with_subject(&patient);
        assert!(patient_ctx.read_report(&report, &patient).is_ok());
    }

    #[test]
    fn test_doctor_report_access_after_assignment() {
        let (enforcer, _, mut patient, doctor) = setup();
        let other_doctor = create_test_user(UserID::new(), "other_doctor", Role::Doctor, false);
        let report = create_test_report(other_doctor.id, patient.id, "Medical Report");

        let doctor_ctx = enforcer.with_subject(&doctor);
        // Doctor shouldn't see report before assignment
        assert!(doctor_ctx.read_report(&report, &patient).is_err());

        // After becoming patient's doctor
        if let Some(ref mut folder) = patient.medical_folder {
            folder.doctors.insert(doctor.id);
        }
        // Doctor should see report
        assert!(doctor_ctx.read_report(&report, &patient).is_ok());
    }

    #[test]
    fn test_multiple_doctors_access() {
        let (enforcer, _, mut patient, doctor1) = setup();
        let doctor2 = create_test_user(UserID::new(), "doctor2", Role::Doctor, false);

        // Add both doctors
        if let Some(ref mut folder) = patient.medical_folder {
            folder.doctors.insert(doctor1.id);
            folder.doctors.insert(doctor2.id);
        }

        let report = create_test_report(doctor1.id, patient.id, "Medical Report");

        // Both doctors should have access
        let doctor1_ctx = enforcer.with_subject(&doctor1);
        let doctor2_ctx = enforcer.with_subject(&doctor2);

        assert!(doctor1_ctx.read_report(&report, &patient).is_ok());
        assert!(doctor2_ctx.read_report(&report, &patient).is_ok());
    }


}
