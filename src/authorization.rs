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

#[cfg(test)]
mod test{
    use std::collections::BTreeSet;
    use crate::models::{BloodType, MedicalFolder, PersonalData, ReportID, UserID};
    use crate::utils::input_validation::{AVSNumber, Username};
    use crate::utils::password_utils::hash;
    use super::*;

    fn setup_enforcer() -> Enforcer {
        Enforcer::load().expect("Failed to load enforcer")
    }

    fn create_patient(doctors: BTreeSet<UserID>) -> UserData {
        let personal_data = PersonalData{
            avs_number : AVSNumber::try_from("756.1234.5678.97".to_string()).unwrap(),
            blood_type : BloodType::A
        };
        UserData {
            id: UserID::new(),
            role: Role::Patient,
            username: Username::new("patient".to_string()),
            password: hash("password"),
            medical_folder: Some(MedicalFolder{
                personal_data,
                doctors,
            }),
        }
    }

    fn create_folder(){
        let personal_data = PersonalData{
            avs_number : AVSNumber::try_from("756.1234.5678.90".to_string()).unwrap(),
            blood_type : BloodType::A
        };
        MedicalFolder::new(personal_data);
    }

    fn create_doctor() -> UserData {
        UserData {
            id: UserID::new(),
            role: Role::Doctor,
            username: Username::new("doctor".to_string()),
            password: hash("password"),
            medical_folder: None,
        }
    }

    fn create_admin() -> UserData {
        UserData {
            id: UserID::new(),
            role: Role::Admin,
            username: Username::new("admin".to_string()),
            password: hash("password"),
            medical_folder: None,
        }
    }

    fn create_report(author: UserID, patient: UserID) -> MedicalReport {
        MedicalReport {
            id: ReportID::new(),
            title: "Test report".to_string(),
            author,
            patient,
            content: "Test content".to_string(),
        }
    }

    #[test]
    fn test_user_can_crud_his_own_data() {
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::default());

        let ctx = enforcer.with_subject(&patient);
        assert!(ctx.read_data(&patient).is_ok());
        assert!(ctx.update_data(&patient).is_ok());
        assert!(ctx.delete_data(&patient).is_ok());
    }

    #[test]
    fn test_user_can_choose_his_doctor() {
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::default());
        let doctor = create_doctor();

        let ctx = enforcer.with_subject(&patient);
        assert!(ctx.add_doctor(&patient, &doctor).is_ok());
        assert!(ctx.remove_doctor(&patient, &doctor).is_ok());
    }

    #[test]
    fn test_doctor_can_read_his_patient_data() {
        let enforcer = setup_enforcer();
        let doctor = create_doctor();
        let patient = create_patient(BTreeSet::from([doctor.id]));

        let ctx = enforcer.with_subject(&doctor);
        assert!(ctx.read_data(&patient).is_ok());
    }

    #[test]
    fn test_doctor_can_add_report_to_any_user_that_has_file() {
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::from([UserID::new()]));
        let doctor = create_doctor();
        let report = create_report(doctor.id, patient.id);

        let ctx = enforcer.with_subject(&doctor);
        assert!(ctx.add_report(&patient, &report).is_ok());
    }

    #[test]
    fn test_report_owner_can_read_and_update_report() {
        
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::default());
        let doctor = create_doctor();
        let report = create_report(doctor.id, patient.id);

        let ctx = enforcer.with_subject(&doctor);
        println!("Testing update_report with subject: {:?}, report: {:?}", ctx.subject, report);
        assert!(ctx.read_report(&report, &patient).is_ok());
        assert!(ctx.update_report(&report).is_ok());
    }

    #[test]
    fn test_doctor_can_read_report_from_his_patient() {
        let enforcer = setup_enforcer();
        let doctor = create_doctor();
        let patient = create_patient(BTreeSet::from([doctor.id]));
        let report = create_report(doctor.id, patient.id);

        let ctx = enforcer.with_subject(&doctor);
        assert!(ctx.read_report(&report, &patient).is_ok());
    }

    #[test]
    fn test_admin_can_do_anything() {
        let enforcer = setup_enforcer();
        let admin = create_admin();
        let patient = create_patient(BTreeSet::default());
        let report = create_report(admin.id, patient.id);
        let doctor = create_doctor();
        let role = Role::Admin;

        let ctx = enforcer.with_subject(&admin);
        assert!(ctx.read_data(&patient).is_ok());
        assert!(ctx.update_data(&patient).is_ok());
        assert!(ctx.delete_data(&patient).is_ok());
        assert!(ctx.add_report(&patient, &report).is_ok());
        assert!(ctx.read_report(&report, &patient).is_ok());
        assert!(ctx.update_report(&report).is_ok());
        assert!(ctx.update_role(&patient, role).is_ok());
        assert!(ctx.add_doctor(&patient, &doctor).is_ok());
        assert!(ctx.remove_doctor(&patient, &doctor).is_ok());
    }

    #[test]
    fn test_patient_cannot_update_data() {
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::default());
        let new_data = create_patient(BTreeSet::default());

        let ctx = enforcer.with_subject(&patient);
        assert!(ctx.update_data(&new_data).is_err());
    }

    // Tests pour les patients
    #[test]
    fn test_patient_own_data_access() {
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::default());
        let ctx = enforcer.with_subject(&patient);

        assert!(ctx.read_data(&patient).is_ok(), "Patient should be able to read their own data");
        assert!(ctx.update_data(&patient).is_ok(), "Patient should be able to update their own data");
        assert!(ctx.delete_data(&patient).is_ok(), "Patient should be able to delete their own data");
    }

    #[test]
    fn test_patient_cannot_access_others_data() {
        let enforcer = setup_enforcer();
        let patient1 = create_patient(BTreeSet::default());
        let patient2 = create_patient(BTreeSet::default());
        let ctx = enforcer.with_subject(&patient1);

        assert!(ctx.read_data(&patient2).is_err(), "Patient should not be able to read other's data");
        assert!(ctx.update_data(&patient2).is_err(), "Patient should not be able to update other's data");
        assert!(ctx.delete_data(&patient2).is_err(), "Patient should not be able to delete other's data");
    }

    #[test]
    fn test_patient_doctor_management() {
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::default());
        let doctor = create_doctor();
        let ctx = enforcer.with_subject(&patient);

        assert!(ctx.add_doctor(&patient, &doctor).is_ok(), "Patient should be able to add doctor");
        assert!(ctx.remove_doctor(&patient, &doctor).is_ok(), "Patient should be able to remove doctor");
    }

    // Tests pour les médecins
    #[test]
    fn test_doctor_patient_access() {
        let enforcer = setup_enforcer();
        let doctor = create_doctor();
        let mut doctors = BTreeSet::new();
        doctors.insert(doctor.id);
        let patient = create_patient(doctors);
        let ctx = enforcer.with_subject(&doctor);

        assert!(ctx.read_data(&patient).is_ok(), "Doctor should be able to read their patient's data");
    }

    #[test]
    fn test_doctor_report_management() {
        let enforcer = setup_enforcer();
        let doctor = create_doctor();
        let patient = create_patient(BTreeSet::default());
        let report = create_report(doctor.id, patient.id);
        let ctx = enforcer.with_subject(&doctor);

        assert!(ctx.add_report(&patient, &report).is_ok(), "Doctor should be able to add report");
        assert!(ctx.update_report(&report).is_ok(), "Doctor should be able to update own report");
    }

    #[test]
    fn test_doctor_patient_report_access() {
        let enforcer = setup_enforcer();
        let doctor = create_doctor();
        let mut doctors = BTreeSet::new();
        doctors.insert(doctor.id);
        let patient = create_patient(doctors);
        let report = create_report(UserID::new(), patient.id); // Report by another doctor
        let ctx = enforcer.with_subject(&doctor);

        assert!(ctx.read_report(&report, &patient).is_ok(),
                "Doctor should be able to read reports of their patients");
    }

    // Tests pour l'administrateur
    #[test]
    fn test_admin_full_access() {
        let enforcer = setup_enforcer();
        let admin = create_admin();
        let patient = create_patient(BTreeSet::default());
        let doctor = create_doctor();
        let report = create_report(doctor.id, patient.id);
        let ctx = enforcer.with_subject(&admin);

        assert!(ctx.read_data(&patient).is_ok(), "Admin should be able to read data");
        assert!(ctx.update_data(&patient).is_ok(), "Admin should be able to update data");
        assert!(ctx.delete_data(&patient).is_ok(), "Admin should be able to delete data");
        assert!(ctx.add_report(&patient, &report).is_ok(), "Admin should be able to add report");
        assert!(ctx.read_report(&report, &patient).is_ok(), "Admin should be able to read report");
        assert!(ctx.update_report(&report).is_ok(), "Admin should be able to update report");
        assert!(ctx.add_doctor(&patient, &doctor).is_ok(), "Admin should be able to add doctor");
        assert!(ctx.remove_doctor(&patient, &doctor).is_ok(), "Admin should be able to remove doctor");
    }

    // Tests négatifs
    #[test]
    fn test_doctor_unauthorized_actions() {
        let enforcer = setup_enforcer();
        let doctor = create_doctor();
        let patient = create_patient(BTreeSet::default()); // Patient without this doctor
        let other_doctor = create_doctor();
        let report = create_report(other_doctor.id, patient.id);
        let ctx = enforcer.with_subject(&doctor);

        assert!(ctx.update_data(&patient).is_err(),
                "Doctor should not be able to update non-patient data");
        assert!(ctx.update_report(&report).is_err(),
                "Doctor should not be able to update other doctor's report");
    }

    #[test]
    fn test_patient_unauthorized_actions() {
        let enforcer = setup_enforcer();
        let patient = create_patient(BTreeSet::default());
        let other_patient = create_patient(BTreeSet::default());
        let doctor = create_doctor();
        let report = create_report(doctor.id, patient.id);
        let ctx = enforcer.with_subject(&patient);

        assert!(ctx.update_report(&report).is_err(),
                "Patient should not be able to update reports");
        assert!(ctx.add_doctor(&other_patient, &doctor).is_err(),
                "Patient should not be able to modify other patient's doctors");
    }
    #[test]
    fn test_admin_can_write_patient_report() {
        let enforcer = setup_enforcer();
        let admin = create_admin();
        let patient = create_patient(BTreeSet::default());
        let report = create_report(admin.id, patient.id); // Rapport créé par l'admin
        let ctx = enforcer.with_subject(&admin);

        // Test d'ajout d'un rapport
        assert!(ctx.add_report(&patient, &report).is_ok(),
                "Admin should be able to add a report for a patient");

        // Test de lecture du rapport
        assert!(ctx.read_report(&report, &patient).is_ok(),
                "Admin should be able to read the report they created");

        // Test de modification du rapport
        assert!(ctx.update_report(&report).is_ok(),
                "Admin should be able to update the report they created");
    }

    #[test]
    fn test_admin_can_manage_any_report() {
        let enforcer = setup_enforcer();
        let admin = create_admin();
        let doctor = create_doctor();
        let patient = create_patient(BTreeSet::default());
        let report = create_report(doctor.id, patient.id); // Rapport créé par un docteur
        let ctx = enforcer.with_subject(&admin);

        // L'admin devrait pouvoir lire et modifier même les rapports créés par d'autres
        assert!(ctx.read_report(&report, &patient).is_ok(),
                "Admin should be able to read any report");
        assert!(ctx.update_report(&report).is_ok(),
                "Admin should be able to update any report");
    }
}

